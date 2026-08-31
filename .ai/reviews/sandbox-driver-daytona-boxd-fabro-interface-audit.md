# Sandbox-driver normalization audit: Daytona, Boxd, and Fabro

Date: 2026-08-31\
Repository baseline: committed implementation through 3318bbc before this document refresh\
External documentation: Daytona documentation version 0.207 and the current Boxd documentation on the audit date

## Goal

This audit defines one normalized `sandbox-driver` surface for Daytona and Boxd. Fabro must be able to consume that surface without branching on the provider.

The goal is not to expose every Boxd feature. Boxd-only features remain out of scope for now. The interface can expose a feature that only Daytona currently supports when Fabro needs it or when it is already part of the intended portable resource model. Boxd reports that capability as unavailable.

Fabro does not use `sandbox-driver` yet. The Fabro column shows behavior that a migration must preserve.

This report now describes committed interface and adapter behavior. It includes snapshot activation, provider health, undelete, range and append file operations, services, output sanitization, bidirectional stdio, PTY, provider logs, web terminals, VNC, sandbox kinds, virtualization, regions, and resource requests.

## Normalization rules

The interface uses these rules:

1. **Capabilities describe behavior, not provider endpoint names.** A capability is true only when the provider meets the complete portable contract.
2. **Capabilities are per sandbox handle.** Daytona class and sandbox state can change which operations are valid. Provider-wide capability claims are not sufficient.
3. **Consumers do not branch on provider kind.** They inspect normalized capabilities and results.
4. **A normalized operation can have provider-specific implementation details.** For example, Boxd can create a proxy internally when `preview_url(port)` needs one.
5. **Provider-only features stay hidden.** They can remain provider defaults or use `provider_config` during early development. They do not get public traits or capability flags yet.
6. **Do not map different destructive or persistence semantics together.** In particular, Boxd hibernate is not archive, and idle destroy is not wall-clock TTL.
7. **Report unavoidable variation in a result.** The execution model already does this with `live_streaming` and `streams_separated`.

## Executive summary

The current interface is close to a useful normalized surface. It does not need broad Boxd-specific expansion.

The main interface decisions are:

1. **Make fork behavior portable.** Define portable fork as a fork of a running sandbox that preserves filesystem, memory, and running processes and returns a running sandbox. Daytona VM fork and Boxd running-machine fork both meet this contract. Remove the caller-controlled `include_memory` Boolean.
2. **Normalize Boxd standby and hibernation as `Paused`.** `resume()` hides whether the provider calls resume or wake. Do not add `Hibernated`, hibernate/wake methods, or auto-hibernate capabilities now.
3. **Use concurrent PTY sessions.** `PtySession` now uses `&self` methods. Fabro can read output while it handles input and resize events.
4. **Keep volumes at the common create-time mount level.** Do not add Boxd runtime disk attach, detach, or read-only attachment now.
5. **Use preview URLs as the common ingress abstraction.** Do not add Boxd proxy, custom-domain, raw-port, or Tailscale management now.
6. **Make SSH return a ready command with optional expiry and revocation.** Daytona returns minted access. A future Boxd adapter can return its stable SSH command. Separate capabilities report TTL and revocation support.
7. **Report Daytona lifecycle and snapshot capabilities by sandbox class.** The adapter obtains the class on create and attach. It masks pause, fork, and live-process snapshot support for unsupported classes.
8. **Remove checkpoint and restore.** They were Boxd-only and had no current consumer. Protocol version 1 keeps compatibility tombstones instead of exposing them in the public Rust API.
9. **Defer secret references and substitution.** They remain out of the current public interface until a consumer needs them.

The current Daytona adapter and plugin protocol now carry long-lived bidirectional stdio, concurrent PTY, normalized output sanitization, entrypoint logs, snapshot build logs, provider web-terminal URLs, and Computer Use/VNC setup. These paths passed live Daytona tests both in process and through JSON-RPC.

The workspace pins daytona-sdk-rust commit 7de0d4ce7cede28d4f46bc58aafc8cb9210c122d. It contains the normalized control-plane surface, bidirectional session input, PTY handles, authenticated log streams, per-create target support, direct live tests, and Daytona v0.207.0 generation metadata.

## Current implementation summary

| Feature | Normalized interface | Daytona implementation | Current result |
| --- | --- | --- | --- |
| Start, stop, archive | Required start/stop plus optional archive | Direct lifecycle calls | Live conformance passed |
| Pause and resume | Optional, class-aware | Pause and start-as-resume for supported VM classes | Present; unsupported classes report false |
| Fork | Optional, class-aware, and strictly live-state preserving | Daytona fork for supported VM classes | Contract and conformance implemented; the test account has no available VM snapshot, so live provider proof remains blocked by account inventory |
| Resize | Optional | Disabled because the current API route returns 404 and the official SDK leaves resize disabled | `lifecycle.resize: false`; normalized method retained |
| Automatic lifecycle and wall-clock TTL | Optional timer fields | Auto-stop, auto-pause, auto-archive, auto-delete, and TTL mapping | Live wall-clock TTL succeeded on a container. Live container auto-pause returned the expected Daytona class-specific rejection. Positive VM auto-pause proof remains blocked by runner availability. |
| Image and Dockerfile snapshots | Optional source capabilities | Direct create plus streamed build logs | Live in-process and wire tests passed |
| Filesystem and live-process snapshots | Separate optional modes and capabilities | Daytona cold/container and hot/VM snapshot mapping | Container filesystem restore passed live; the test account has no available VM snapshot for the hot path |
| Snapshot get, list, activate, deactivate, delete | Optional provider service | Direct mapping with activation retry while deactivation settles | Live round trip passed |
| Volume create, mount-at-create, list, delete | Optional provider service and create spec | Direct mapping | Included in full live conformance |
| Filesystem and Git | Required filesystem plus derived/native Git | Native Daytona files; derived Git remains available | Included in full live conformance |
| Streaming process output | Optional execution flags | Live stdout and stderr with separate stream identity | Live in-process and wire conformance passed |
| Output sanitization | Public `Raw`, `StripAnsi`, and `StripAll` execution policy | Applied consistently to buffered results, streaming sinks, retained output, and capture statistics | Raw remains the default; live Daytona conformance passed |
| Bidirectional stdio and cancellation | Optional `exec.stdio_process` and `exec.cancel` | Daytona command sessions; UTF-8 command-session payload limit | Live in-process and wire conformance passed |
| PTY | Optional concurrent facet | Daytona PTY WebSocket with independent output and control locks | Live bidirectional in-process and wire tests passed |
| Provider and snapshot logs | Optional log facets | Entrypoint logs and snapshot build logs | Shared conformance verifies output delivery, sink-error propagation, and dropped-future cancellation. Focused live in-process and wire tests passed. |
| Preview URLs and HTTPS | Optional standard and signed URLs | Direct Daytona preview APIs | Live test passed |
| Web terminal | Optional URL facet | Signed port 22222 preview URL | Focused live wire test passed |
| SSH | Ready command with optional TTL, token, expiry, and revocation | Daytona time-limited access with TTL and revoke capabilities | Live test and conformance passed |
| VNC | Optional browser connection facet | Starts Computer Use, then returns a signed noVNC URL | Focused live wire test passed |
| CIDR egress limits | Optional creation and live-update policy | Daytona network allow list mapping | Live deny-at-create and allow-after-update test passed |
| Tailscale or another VPN client | No sandbox-driver interface | Install and configure through `Exec` | Intentionally outside this library |

## Normalized lifecycle matrix

| Feature | Normalized contract | Daytona mapping | Boxd mapping | Fabro use and decision |
| --- | --- | --- | --- | --- |
| Start and stop | Required. `start()` makes the sandbox runnable. `stop()` preserves persistent disk. | Direct support for all documented classes. | Direct support. | **Used. Keep.** |
| Resize | Optional `lifecycle.resize`. The request uses normalized CPU, memory, disk, and GPU fields. Provider constraints return a clear invalid-state or invalid-spec error. | Report false. Live verification found a route-level 404, and the current official SDK leaves resize disabled. Creation-time resources still work. | Runtime resize is not documented. Report false. Creation-time resource selection still uses `SandboxSpec.resources`. | **Not used by Fabro. Keep the existing optional capability, but do not claim Daytona support.** |
| Archive | Optional `lifecycle.archive`. Archive means stopped disk state moved to cold storage. `start()` restores it. | Container sandboxes support it. Other classes report false. | Report false. Do not map hibernate to archive. | **Not used. Keep because it is an intended Daytona lifecycle operation.** |
| Pause and resume | Optional `lifecycle.pause`. `pause()` suspends execution while preserving memory. `resume()` makes it runnable again. Observed provider states with these consumer semantics normalize to `Paused`. | Linux VM and Windows support direct pause/resume. Other classes report false. | `pause()` uses standby. `resume()` uses resume. A provider-reported hibernated machine also describes as `Paused`; `resume()` uses wake internally. | **Not used. Keep one normalized capability. Do not add hibernate/wake.** |
| Fork | Optional `lifecycle.fork`. Source must be `Running`. The fork preserves filesystem, memory, and running process state. The returned sandbox is `Running`. | Started VM fork matches. Container classes report false. | Running-machine fork matches. Stopped disk-only fork is not exposed by the portable method. | **Not used by Fabro. Keep one strict normalized operation. Remove `include_memory`.** |
| Automatic stop after idle | Optional timer. Provider-specific activity rules must be documented in status or provider documentation. | Direct auto-stop mapping. | No exact stop mapping is needed. Report unsupported if Boxd cannot provide the same transition. | **Used by Fabro for Daytona with a 120-minute default. Keep.** |
| Automatic pause after idle | Optional timer. The resulting normalized state is `Paused`. | Direct auto-pause mapping for supported VM classes. | Map to auto-suspend. Later provider-driven hibernation remains hidden and still describes as `Paused`. | **Not used. Keep as the common suspend behavior.** |
| Automatic archive after stop | Optional timer with exact archive semantics. | Direct mapping for container sandboxes. | Report unsupported. Do not map auto-hibernate. | **Not used. Keep as an existing Daytona capability.** |
| Automatic delete after stop | Optional timer. The clock begins only after the normalized state becomes `Stopped`. | Direct mapping. | Report unsupported. Boxd idle `autoDestroyTimeout` has different semantics. | **Not used. Keep the exact contract.** |
| Wall-clock TTL | Optional timer. Lifetime runs independently of state and idle activity. | Implemented through Daytona's TTL setting. | Report unsupported. Do not map idle auto-destroy to TTL. | **Not used. Keep the exact contract.** |
| Activity refresh | Optional keepalive for providers whose idle policy supports explicit refresh. | Direct support. | Report unsupported unless Boxd documents an equivalent guarantee. | **Not used. Keep optional.** |
| Checkpoint and restore | Not part of the public interface. Protocol version 1 recognizes the old names only as compatibility tombstones. | No mapping. | Boxd support remains provider-only. | **Not used. Removed because it is Boxd-only.** |

### Lifecycle decisions

The normalized state model does not need a Boxd-only `Hibernated` variant. A consumer needs to know whether execution is active, suspended with state preserved, stopped with disk preserved, or archived. A Boxd adapter can retain the raw standby-versus-hibernated state internally so that `resume()` dispatches the correct provider call.

The fork contract is strict instead of configurable. Both providers can preserve live process state when the source is running. This gives consumers one reliable meaning:

- Source state: `Running`.
- Filesystem state: preserved.
- Memory state: preserved.
- Running processes and PIDs: preserved where the provider guarantees PID restoration.
- Result state: `Running`.

Boxd's stopped disk-only fork remains a provider-only operation. Daytona's inability to fork a stopped VM is no longer a portability problem.

The current timer type can remain. The provider reports unsupported fields before creation or update. The interface should not add auto-hibernate or idle auto-destroy until another provider or Fabro needs those exact semantics.

## Normalized snapshot and volume matrix

| Feature | Normalized contract | Daytona mapping | Boxd mapping | Fabro use and decision |
| --- | --- | --- | --- | --- |
| Snapshot create from image or Dockerfile | Optional source capabilities. Creation returns an opaque `SnapshotId`. | Direct support. | Report unsupported when the source type is not available. | **Used by Fabro on Daytona. Keep.** |
| Live snapshot with process state | Optional `SnapshotMode::LiveProcessState`; capability `snapshots.live_process_state_from_sandbox`. Source must be running. Memory, running processes, and process IDs are preserved when a sandbox is created from it. | Map to a hot VM snapshot with memory. Unsupported classes report false. The test account has no available general Linux VM snapshot, so the live provider path could not run. | Native running-machine snapshot matches. | **Not used by Fabro. Implemented as a distinct semantic mode.** |
| Filesystem-only sandbox snapshot | Optional `SnapshotMode::Filesystem`; capability `snapshots.filesystem_from_sandbox`. The source must be stopped for Daytona. It does not promise memory or process restoration. | Map to a cold/container snapshot. A live container test verified that files restore and running processes do not. | Report unsupported if Boxd cannot provide the same filesystem-only contract. | **Not used. Implemented separately from live snapshot semantics.** |
| Snapshot get | Get one exact opaque ID. | Direct support. | Direct SDK support. | **Used. Keep.** |
| Snapshot list | Return normalized status values and opaque IDs. Names are labels, not stable selectors. | Direct support. | Direct support. Multiple Boxd versions can appear as separate opaque IDs. | **Not used, but part of common management. Keep.** |
| Snapshot delete | Delete one exact opaque ID. | Direct support. | Direct support. The Boxd adapter resolves the opaque ID to the correct provider version. | **Not used, but common. Keep.** |
| Snapshot activate and deactivate | Optional `snapshots.activation`. | Direct support. | Report false. | **Not used. Keep the existing Daytona capability because activation is already in scope.** |
| Snapshot versions | No public version API. IDs identify exact snapshots. Names are only filters and display values. | No special mapping. | Hide Boxd name-version behavior behind opaque IDs. | **Do not add Boxd-only version selectors now.** |
| Volume create, get, list, delete | Common provider-level management with opaque IDs. | Direct support. | Map Boxd disks to normalized volumes. | **Not used, but common. Keep.** |
| Volume mount | Mount only through `SandboxSpec.volumes` at sandbox creation. | Direct create-time mount. | Use Boxd creation-time disk configuration. | **Not used. Keep the common creation path.** |
| Runtime attach, detach, and read-only mode | Not part of the normalized interface. | No loss for Daytona. | Provider-only Boxd features remain hidden. | **Do not add now.** |

### Snapshot and volume decisions

The interface replaces Boolean memory requests with semantic snapshot modes. `SnapshotMode::Filesystem` promises filesystem state only. `SnapshotMode::LiveProcessState` also promises memory, running processes, and process IDs. The capability says which contract the provider can meet.

Opaque snapshot IDs avoid a Boxd-only version API. An adapter can encode or store the provider name and version needed to get or delete one exact snapshot. Consumers must not use a snapshot name as identity.

Create-time volume mounts are the portable intersection. `VolumeMount` documents this as a deliberate portable boundary. It does not claim that every provider lacks runtime attachment.

## Normalized execution, filesystem, and Git matrix

| Feature | Normalized contract | Daytona mapping | Boxd mapping | Fabro use and decision |
| --- | --- | --- | --- | --- |
| Filesystem operations | Required portable filesystem facet. Native and exec-derived implementations have the same behavior. | Use native operations. | Use native upload/download and derived shell operations for the remainder. | **Heavily used. Current surface fits.** |
| Git operations | Optional native facet with an exec-derived fallback. Credentials remain per call or caller-managed. | Native operations are available. The current adapter can continue with derived Git until native use is needed. | Use derived Git in the full VM. | **Heavily used. Current surface fits.** |
| Buffered execution | Required Bash contract with working directory, environment, timeout, output buffers, and termination reason. | Direct support. | Direct support through an explicit Bash wrapper. | **Heavily used. Keep.** |
| Finite stdin | Optional `exec.stdin`. Write exact bytes, close stdin, then wait. | Direct support. | Direct support through streaming execution. | **Used. Keep.** |
| Long-lived bidirectional stdio | Optional `exec.stdio_process`. Independent stdin/stdout plus a bounded stderr tail. | Implemented with command sessions and carried through the plugin protocol. The current upstream session payload is UTF-8. | Streaming exec can support it. | **Used by ACP. Daytona and the protocol now support it.** |
| Streaming output | Optional live delivery. Every result reports live versus replayed and separate versus combined. | Direct live, separated output. | Non-PTY output can be separate. PTY output is combined. | **Heavily used. Current honesty flags fit both.** |
| Output sanitization | `ExecSpec` selects `Raw`, `StripAnsi`, or `StripAll`. Filtering occurs before sink delivery, retention, and capture accounting. PTY and long-lived stdio stay raw. | Stateful filtering covers one-shot execution and command-session streams. | The adapter applies the same provider-neutral policy. | **Common public behavior for all consumers. Raw remains compatible and binary-safe.** |
| Cancellation | Optional `exec.cancel`. A cancelled result requires a best-effort remote process-group kill, not only cancellation of the local wait. | Direct support. | Report false until the adapter proves remote termination. | **Used. Keep the strict contract.** |
| PTY | Optional facet with open, concurrent input/output, resize, and close. Output is combined terminal output. | Implemented over the PTY WebSocket and carried through the plugin protocol. | Direct support. | **Used by the Fabro web terminal. Implemented and live verified.** |
| Provider logs | Follow-only optional facet for provision and entrypoint logs. Process logs use `Exec`. | Entrypoint log streaming is implemented and carried through the plugin protocol. Provision logs remain false. | Report unsupported if there is no matching provider source. | **Exposed without adding Boxd behavior.** |

### Execution decisions

The execution model already shows the right normalization pattern. It exposes one operation and reports degradation through `live_streaming` and `streams_separated`. A Boxd PTY reports combined output. Non-PTY execution can report separate streams.

Output sanitization is also provider-neutral. `Raw` preserves the previous behavior. `StripAnsi` removes ANSI terminal escape sequences. `StripAll` additionally removes standalone C0/C1 control characters except tab, line feed, and carriage return. The filter keeps state across stream chunks so a split escape sequence cannot leak. PTY and bidirectional stdio stay raw because they are terminal transports, not captured command output.

`PtySession` now uses concurrent `&self` methods with internal synchronization. Fabro's current `tokio::select!` loop can read output while it accepts input and resize messages.

The finite stdin operation does not replace `spawn_stdio`. Fabro needs both. The plugin protocol now carries long-lived stdio and PTY, so a future Boxd plugin can implement current Fabro behavior without a protocol extension.

## Normalized access, ingress, network, and secrets matrix

| Feature | Normalized contract | Daytona mapping | Boxd mapping | Fabro use and decision |
| --- | --- | --- | --- | --- |
| Standard preview URL | `preview_url(port)` returns a URL and required headers. The method may idempotently ensure provider routing for that port. | Return the normal preview URL and token header when private. | Return the machine HTTPS URL. For a non-default port, the adapter can ensure a named proxy internally. | **Used. This is the common ingress abstraction.** |
| Signed preview URL | Optional capability returning an expiring URL without required headers. | Direct support. | Report false. | **Used by Fabro for user previews and noVNC. Keep optional.** |
| Signed preview revocation | Optional follow-up behavior using a returned token. | Daytona can support it. | Report false. | **Not used today. Add only if Fabro needs early revocation.** |
| HTTPS | A property of the returned preview URL, not a separate managed resource. | Preview URLs use HTTPS. | Machine and proxy URLs use managed HTTPS. | **Used through previews. No new interface.** |
| Port proxies | An adapter implementation detail of `preview_url(port)` for now. | Daytona uses its preview routing. | The adapter can use the default route or an idempotently managed named proxy. | **Do not add proxy CRUD.** |
| Custom domains | Outside the normalized interface. | Customer-operated preview proxy configuration remains external. | Boxd custom-domain management remains provider-only. | **Not used. Do not add.** |
| Web terminal | Optional provider URL facet, but portable consumers should build on PTY. | Implemented as a signed preview URL for Daytona's terminal port and carried through the plugin protocol. | Not documented. Report false. | **Exposed for callers that want the provider terminal. Fabro can still host its own PTY terminal.** |
| SSH | `ssh_access(None)` returns a ready command. A provider can return stable access or its default temporary lifetime. `ssh_access(Some(ttl))` must honor the TTL or return `Unsupported(access.ssh.ttl)`. Token, expiry, and revocation are optional. | Mint time-limited access and return its command, token, and expiry. Report TTL and revoke support separately. | Return stable `ssh <name>.boxd` access with no token or expiry. Report TTL and revoke as unsupported unless Boxd adds those guarantees. | **Used. Implemented without requiring provider-specific checks.** |
| VNC | Optional connection facet. `vnc_connection()` can ensure the provider desktop service is running before it returns a URL. | Implemented: start Computer Use, then return a signed noVNC URL. The plugin protocol carries the result. | Report false. | **Used on Daytona. Implemented without Boxd behavior.** |
| Tailscale VPN | No sandbox-driver interface. | In-guest setup is caller automation through `Exec`. | Organization-level tailnet routing remains external configuration. | **Do not add a VPN facet.** |
| Egress allow, block, and CIDR list | Existing optional creation policy plus optional live update. | Direct support. | Report unsupported. | **Fabro uses create-time Daytona policy. Keep.** |
| Domain egress allow list | Existing optional policy. | Direct support. | Report unsupported. | **Not used. Keep as an existing general network policy.** |
| Outbound HTTP(S) proxy | No normalized creation field yet. `NetworkPolicy` remains about enforcement rules. | Available through Daytona `provider_config.outbound_proxy_url`; no normalized capability is claimed. | Report unsupported. | **Not used. Add a common request field only when a consumer needs it.** |
| East-west named networks | Outside the normalized interface. | No mapping needed. | Boxd feature remains hidden. | **Do not add.** |
| Secret reference | Deferred. There is no public secret-reference input yet. | Daytona support is not exposed. | Boxd support is not exposed. | **Not used. Add only when a consumer defines the required contract.** |
| Secret substitution | Deferred. There is no public substitution capability yet. | Daytona support is not exposed. | Boxd plaintext environment injection does not meet Daytona's substitution semantics. | **Not used. Keep out of this arc.** |

### Access and network decisions

`PreviewUrls` is the uniform ingress surface. Consumers ask for access to a port. They do not manage Boxd proxy names or Daytona routing internals. The operation must be idempotent because a Boxd adapter can need to create a proxy for a non-default port.

Do not add custom-domain, raw-port, Tailscale, or named-network traits now. Tailscale is guest software that callers configure through `Exec`. The other features do not have matching Daytona and Boxd sandbox semantics, and Fabro does not use them.

The SSH trait is normalized around a ready command. It keeps token and expiry optional. `AccessCaps::ssh_ttl` and `AccessCaps::ssh_revoke` let a consumer request those stronger behaviors without provider checks.

Secret references and substitution remain deferred. Their delivery and security semantics differ. The public interface should add them only when a consumer can define the required behavior.

## Capability matrix for consumers

This table shows the intended per-handle capability result. Daytona values vary by sandbox class. Boxd values assume the documented standard machine behavior.

| Normalized capability | Daytona | Boxd | Fabro requires now |
| --- | --- | --- | --- |
| `lifecycle.start_stop` | Yes | Yes | Yes |
| `lifecycle.resize` | No with the current API and SDK | No documented runtime support | No |
| `lifecycle.archive` | Container only | No | No |
| `lifecycle.pause` | Linux VM and Windows | Yes | No |
| `lifecycle.fork` | Linux VM and Windows | Yes for a running source | No |
| `lifecycle.timers.auto_stop` | Yes | No exact mapping | Yes for Daytona |
| `lifecycle.timers.auto_pause` | Supported VM classes | Yes through auto-suspend | No |
| `lifecycle.timers.auto_archive` | Container only | No | No |
| `lifecycle.timers.auto_delete_after_stop` | Yes | No exact mapping | No |
| `lifecycle.timers.ttl` | Yes | No | No |
| `snapshots.from_image` | Yes | No documented mapping | Yes for Daytona |
| `snapshots.from_dockerfile` | Yes | No documented mapping | Yes for Daytona |
| `snapshots.filesystem` | Yes; cold snapshot rules vary by class | Only if the adapter can guarantee filesystem-only capture | No |
| `snapshots.live_process_state` | VM hot snapshot | Yes for a running source | No |
| `snapshots.activation` | Yes | No | No |
| `volumes.create_time_attach` | Yes | Yes | No |
| `exec.stdin` | Yes | Yes | Yes |
| `exec.live_streaming` | Yes | Yes | Yes |
| `exec.streams_separated` | Yes outside PTY | Yes outside PTY | Yes when available |
| `exec.stdio_process` | Yes, including over JSON-RPC | Yes | Yes |
| `exec.cancel` | Yes | Adapter must prove remote kill | Yes |
| `pty` | Yes, including over JSON-RPC | Yes | Yes |
| `access.preview_urls` | Yes | Yes | Yes |
| `access.signed_preview_urls` | Yes | No | Yes for Daytona |
| `access.ssh` | Yes, ephemeral | Yes, stable | Yes |
| `access.ssh.ttl` | Yes | No documented support | No |
| `access.ssh.revoke` | Yes | No documented support | No |
| `access.web_terminal` | Yes, including over JSON-RPC | No documented support | Optional |
| `access.vnc` | Yes | No documented support | Yes for Daytona |
| `logs.entrypoint` | Yes, including over JSON-RPC | No documented mapping | Optional |
| `snapshots.build_logs` | Yes, including over JSON-RPC | Provider-dependent | Yes for Daytona builds |
| `network.cidr_allow_list` | Yes | No documented support | Optional Fabro setting |
| `network.domain_allow_list` | Yes | No documented support | No |
| `network.outbound_proxy` | No normalized claim; Daytona escape hatch only | No documented support | No |

No capability in this table is Boxd-only.

## Daytona adapter fit

The current adapter covers start/stop/delete, archive, class-aware pause and fork, all lifecycle timers including wall-clock TTL, files, buffered and streaming commands, finite stdin, cancellation, bidirectional stdio, concurrent PTY, image and Dockerfile snapshots, streamed snapshot build logs, snapshot management and activation, volumes, provider entrypoint logs, standard and signed previews, provider web terminals, SSH, VNC, and creation-time or runtime CIDR network policy.

Create and attach obtain the Daytona sandbox class and narrow pause, fork, and live-process snapshot claims for unsupported classes. Resize remains in the normalized interface, but the adapter reports it as unsupported because current live API verification returned a route-level 404 and the official SDK leaves its resize method disabled.

The Daytona SDK now honors a per-create target. The adapter maps `SandboxSpec.region` to that target. Secret references and substitution are explicitly deferred.

## Boxd adapter fit

A Boxd adapter can implement the normalized surface for start/stop/delete, pause/resume, running-state fork, create-time resources, exec, streaming stdin, long-lived stdio, PTY, files, derived Git, live snapshots, basic volume management and creation-time mounting, HTTPS preview URLs, and SSH commands.

The adapter should hide or leave unsupported these Boxd-only features:

- The public distinction between standby and hibernated.
- Explicit hibernate/wake control and auto-hibernate policy.
- Stopped disk-only fork.
- Idle auto-destroy.
- Snapshot version selectors.
- Checkpoint collection management.
- Runtime disk attach/detach and read-only mode.
- Proxy CRUD, raw ports, and custom-domain CRUD.
- Named east-west networks and sandbox isolation flags.
- Organization-level Tailscale management.

The adapter can still use these features internally. For example, it can wake a hibernated sandbox in `resume()` and manage a named proxy inside `preview_url(port)`.

It must report `exec.cancel` as false until cancellation proves that the remote process or process group is gone.

## Fabro migration coverage

The normalized core has a place for almost every feature Fabro uses today:

- Start, stop, delete, and idempotent activation.
- Auto-stop configuration.
- Snapshot get and create from images or Dockerfiles.
- Filesystem, search, and Git operations.
- Buffered execution, live output, finite stdin, cancellation, and long-lived stdio.
- PTY.
- Standard and signed preview URLs.
- SSH.
- Optional Daytona VNC.

This arc closed the four implementation gaps found in the first audit:

1. PTY allows concurrent read, input, resize, and close.
2. The Daytona adapter implements long-lived stdio and PTY.
3. Daytona VNC starts Computer Use before returning the signed noVNC connection.
4. The plugin protocol carries stdio, PTY, provider logs, snapshot build logs, web terminals, and VNC.

Fabro does not need provider resize, pause, archive, fork, TTL, volume management, Tailscale, proxy CRUD, custom domains, runtime network changes, or provider secret delivery today.

## Plugin protocol

Protocol version 1 now carries core lifecycle, buffered and streaming exec, finite stdin, cancellation, long-lived bidirectional stdio, concurrent PTY, provider logs, snapshot build logs, filesystem operations, snapshots, volumes, preview URLs, provider web-terminal URLs, VNC connections, and normalized SSH access.

The version 1 adapters preserve old fork and snapshot Boolean fields on the wire. New public calls map them to the strict fork and semantic snapshot modes. Old checkpoint method names remain protocol tombstones and return method-not-found.

Do not add protocol methods for Boxd checkpoint collections, runtime disks, proxies, custom domains, Tailscale, or named networks now.

## Recommended changes

### Completed in this arc

1. **Changed PTY concurrency.** The trait uses `&self`, and the Daytona output path has a lock independent from input and control.
2. **Implemented Daytona stdio and PTY.** Provider-neutral and live Daytona conformance tests cover the paths.
3. **Implemented VNC through the existing facet.** `vnc_connection()` starts Computer Use and returns the signed noVNC URL.
4. **Added stdio, PTY, logs, snapshot build logs, web terminals, and VNC to the plugin protocol.**
5. **Made fork running-only and state-preserving.** `ForkOptions::include_memory` is gone. The contract requires a running source and result with filesystem, memory, processes, and process IDs preserved.
6. **Kept Boxd suspended states normalized to `Paused`.** No public hibernate operations were added.
7. **Replaced snapshot `include_memory` with semantic modes.** Filesystem-only and live-process-state support have separate capabilities.
8. **Made Daytona capabilities class-aware and per handle.** Create and attach narrow pause, fork, and live-process snapshot claims.
9. **Normalized SSH around a ready command.** TTL and revocation have separate capability flags.
10. **Removed public checkpoint and restore methods.** Protocol compatibility tombstones remain.
11. **Updated and verified the Daytona SDK pin.** The adapter honors `SandboxSpec.region`. Shared log-follow conformance, direct SDK live coverage, Daytona v0.207.0 regeneration, and the final 151-test driver gate are complete.

### Deferred

12. **Add provider secret references only when needed.** Preserve the distinction between references and Daytona egress-time substitution.
13. **Add signed-preview revocation only when a consumer needs it.** Do not expand preview management into generic proxy or domain CRUD.

## Conformance additions

The conformance suite now tests concurrent PTY, bidirectional stdio, stream identity, cancellation, capability and facet consistency, strict fork behavior, snapshot-mode capability failures, SSH TTL and revoke behavior, and Logs::follow output, sink errors, and drop cancellation. The routine driver gate passed 151 tests. The complete live Daytona package run passed in-process conformance, wire conformance, and eight focused tests.

The following provider-specific proof remains:

- `Paused` resume works for both directly paused and provider-hibernated Boxd machines.
- Preview URL creation is idempotent for a port.
- SSH returns a runnable command for both ephemeral and stable providers.
- Daytona VM fork and live-process snapshots restore the same process IDs. The current test organization cannot run this test because Daytona reports no available general Linux VM snapshot in either tested region.

Future Boxd provider tests should cover its internal pause-versus-wake dispatch and stable SSH command.

## Explicit non-goals

Do not add these Boxd-only capabilities now:

- `Hibernated` state or hibernate/wake methods.
- Auto-hibernate or idle auto-destroy policy.
- Stopped disk-only fork.
- Snapshot version selectors.
- Checkpoint and restore methods or checkpoint collection management.
- Runtime disk attach/detach or read-only attachment.
- Proxy, raw-port, or custom-domain CRUD.
- Named east-west network management or a Boxd sandbox flag.
- Organization Tailscale management.

These decisions can change when Fabro needs a feature or a second provider offers matching semantics.

## Sources

### Local interface and adapter

- [`crates/sandbox-driver/src/sandbox.rs`](../../crates/sandbox-driver/src/sandbox.rs) — lifecycle and facet traits.
- [`crates/sandbox-driver/src/spec.rs`](../../crates/sandbox-driver/src/spec.rs) — resources, network policy, create-time volume mounts, and lifecycle timers.
- [`crates/sandbox-driver/src/provider.rs`](../../crates/sandbox-driver/src/provider.rs) — snapshot and volume management.
- [`crates/sandbox-driver/src/exec.rs`](../../crates/sandbox-driver/src/exec.rs) — execution, stdin, streaming, cancellation, and stdio contracts.
- [`crates/sandbox-driver/src/pty.rs`](../../crates/sandbox-driver/src/pty.rs) — PTY API.
- [`crates/sandbox-driver/src/access.rs`](../../crates/sandbox-driver/src/access.rs) — preview, SSH, web terminal, and VNC facets.
- [`crates/sandbox-driver/src/capabilities.rs`](../../crates/sandbox-driver/src/capabilities.rs) — advertised capability model.
- [`crates/sandbox-driver-daytona/src/lib.rs`](../../crates/sandbox-driver-daytona/src/lib.rs) — current Daytona adapter.
- [`crates/sandbox-driver-protocol/src/methods.rs`](../../crates/sandbox-driver-protocol/src/methods.rs) and [`client.rs`](../../crates/sandbox-driver-protocol/src/client.rs) — plugin protocol surface, including stdio, PTY, logs, web terminals, and VNC.
- [`brynary/daytona-sdk-rust@7de0d4c`](https://github.com/brynary/daytona-sdk-rust/commit/7de0d4ce7cede28d4f46bc58aafc8cb9210c122d) — direct live SDK coverage, Daytona v0.207.0 generation metadata, log streaming, and per-create target selection.

### Fabro

- `~/p/fabro-sh/fabro/lib/components/fabro-sandbox/src/sandbox.rs` — current Fabro sandbox trait.
- `~/p/fabro-sh/fabro/lib/components/fabro-sandbox/src/terminal.rs` — concurrent terminal session contract.
- `~/p/fabro-sh/fabro/lib/components/fabro-sandbox/src/daytona/mod.rs` — Daytona lifecycle, snapshots, exec, preview, SSH, and 120-minute auto-stop default.
- `~/p/fabro-sh/fabro/lib/apps/fabro-server/src/server/handler/sandbox.rs` — web terminal, signed previews, SSH, service discovery, and VNC/Computer Use.
- `~/p/fabro-sh/fabro/lib/components/fabro-acp/src/transport.rs` — bidirectional stdio use.
- `~/p/fabro-sh/fabro/lib/components/fabro-agent/src/tools.rs` — separate and combined output handling.

### Daytona documentation

- [Sandboxes and lifecycle](https://www.daytona.io/docs/en/sandboxes)
- [Snapshots](https://www.daytona.io/docs/en/snapshots)
- [Volumes](https://www.daytona.io/docs/en/volumes)
- [Filesystem operations](https://www.daytona.io/docs/en/file-system-operations)
- [Git operations](https://www.daytona.io/docs/en/git-operations)
- [Process execution](https://www.daytona.io/docs/en/process-code-execution)
- [PTY](https://www.daytona.io/docs/en/pty)
- [Log streaming](https://www.daytona.io/docs/en/log-streaming)
- [Web terminal](https://www.daytona.io/docs/en/web-terminal)
- [SSH access](https://www.daytona.io/docs/en/ssh-access)
- [VNC access](https://www.daytona.io/docs/en/vnc-access)
- [VPN connections](https://www.daytona.io/docs/en/vpn-connections)
- [Preview URLs](https://www.daytona.io/docs/en/preview)
- [Custom preview proxy](https://www.daytona.io/docs/en/custom-preview-proxy)
- [Network limits](https://www.daytona.io/docs/en/network-limits)
- [Secrets](https://www.daytona.io/docs/en/secrets)

### Boxd documentation

- [Forking machines](https://docs.boxd.sh/guides/fork)
- [Suspend and resume](https://docs.boxd.sh/guides/suspend-resume)
- [Checkpoints](https://docs.boxd.sh/guides/checkpoints)
- [Snapshots](https://docs.boxd.sh/guides/snapshots)
- [Resources](https://docs.boxd.sh/guides/resources)
- [TypeScript SDK reference](https://docs.boxd.sh/reference/typescript-sdk)
- [File operations](https://docs.boxd.sh/guides/file-operations)
- [HTTPS](https://docs.boxd.sh/guides/https)
- [Proxies](https://docs.boxd.sh/guides/proxies)
- [Custom domains](https://docs.boxd.sh/guides/custom-domains)
- [Tailscale](https://docs.boxd.sh/guides/tailscale)
- [Sandbox isolation](https://docs.boxd.sh/use-cases/sandboxes)
- [Environment secrets](https://docs.boxd.sh/guides/env-secrets)

## Unresolved questions

None. The fork, snapshot, checkpoint, SSH, and secret-scope decisions are confirmed.
