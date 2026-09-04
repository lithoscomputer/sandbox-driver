# sandbox-driver plugin protocol, version 1

This is the normative specification of the wire protocol between a
**host** (an application embedding `sandbox-driver`, such as fabro) and a
**plugin** (an executable serving one sandbox provider). It is written so
a plugin can be implemented in any language without reading the Rust
source. The Rust implementation lives in the `sandbox-driver-protocol`
crate: `serve_stdio()` is the plugin side, `PluginProvider` the host
side, and the compatibility tests in
`crates/sandbox-driver-protocol/tests/` verify the encodings and
tolerance rules shown here — behaviorally, not as full-shape pins.

Normative words: **must**, **must not**, **may**.

## 1. Model

A plugin serves exactly one provider **kind** (e.g. `e2b`) and
multiplexes every sandbox of that kind over one connection. The host
speaks first and drives the conversation; the plugin answers requests
and emits notifications. One plugin process per provider kind, not per
sandbox.

The protocol is a serialization of the `sandbox-driver` trait family:
anything expressible over the wire is expressible in-process and vice
versa, minus the capability mask in §5.

## 2. Transport and framing

- The transport is the plugin's **stdin/stdout**. Stdout belongs
  exclusively to the protocol; a plugin must log to stderr only. The
  host may leave the plugin's stderr inherited or capture it.
- Messages are **newline-delimited JSON** (NDJSON): one complete JSON
  object per line, UTF-8, terminated by `\n`. A message must not contain
  a raw newline. Blank lines are ignored.
- Either side may have any number of requests outstanding.
  **Responses may arrive in any order**; the `id` correlates them. A
  plugin must not serialize request handling: a slow call must not
  block an unrelated fast call (see §9 and the conformance suite's
  interleaving checks).

## 3. Message envelope

A restricted JSON-RPC 2.0: `jsonrpc` is always `"2.0"`, ids are unsigned
integers, and batches are not used.

Request (has `id` and `method`):

```json
{"jsonrpc":"2.0","id":7,"method":"sandbox/describe","params":{"sandbox_id":"sb-1"}}
```

Success response (has `id` and `result`):

```json
{"jsonrpc":"2.0","id":7,"result":{"status":{"...":"..."}}}
```

Error response (has `id` and `error`, see §7):

```json
{"jsonrpc":"2.0","id":7,"error":{"code":-32000,"message":"...","data":{"...":"..."}}}
```

Notification (has `method`, no `id`; never answered):

```json
{"jsonrpc":"2.0","method":"exec/output","params":{"...":"..."}}
```

In version 1 the host sends only requests; the plugin sends responses
and the notifications `exec/output`, `host/event`, and `host/log`.
Unknown notifications must be ignored. A request with an unknown method
must be answered with error code `-32601`.

## 4. Handshake

The host's first request must be `initialize`:

```json
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocol_version":1}}
```

The plugin answers with its protocol version, identity, and capability
set:

```json
{
  "jsonrpc":"2.0","id":1,
  "result":{
    "protocol_version":1,
    "provider":{"kind":"host","version":"0.1.0"},
    "capabilities":{"...":"see §5"}
  }
}
```

Versioning is a single integer. If the versions differ, each side must
fail with a human-readable message naming both versions — never a decode
error. `provider.kind` is the plugin's declared kind: lowercase ASCII
letters, digits, and interior hyphens, at most 64 bytes. A host that
launched the plugin from configuration must refuse a plugin whose
declared kind differs from the configured kind (§12).

## 5. Capabilities

The capability set is negotiated once at `initialize` and is immutable
for the connection. Per-sandbox capability sets travel in every
`HandleInfo` (§8.1) and are authoritative for that sandbox. The shape
(all fields present; booleans default false; `pty`, `logs`, `snapshots`,
`volumes` are nullable objects):

```json
{
  "isolation": "none | container | vm",
  "lifecycle": {"pause":false,"archive":false,"fork":false,
                 "resize":false,"recover":false,"undelete":false,
                 "refresh_activity":false,
                 "timers":false,"labels":false,"update_network":false,
                 "snapshot_sandbox":false},
  "exec": {"live_streaming":false,"streams_separated":false,"stdin":false,
            "cancel":false,"stdio_process":false,
            "stdin_stream":false,"environment":false},
  "fs": {"native":false,"upload":false,"download":false,"permissions":false},
  "search": {"supported":false,"native":false},
  "git": {"supported":false,"native":false},
  "services": {"supported":false,"native":false},
  "pty": null,
  "logs": null,
  "access": {"preview_urls":false,"signed_preview_urls":false,"ssh":false,
              "ssh_ttl":false,"ssh_revoke":false,
              "shell_command":false,"web_terminal":false,"vnc":false,"vpn":false},
  "network": {"allow_all":false,"block_all":false,"cidr_allow_list":false,
               "domain_allow_list":false,"outbound_proxy":false},
  "snapshots": {"from_image":false,"from_dockerfile":false,
                 "from_image_kinds":{"container":false,"virtual_machine":false},
                 "from_dockerfile_kinds":{"container":false,"virtual_machine":false},
                 "filesystem_from_sandbox":false,
                 "live_process_state_from_sandbox":false,
                 "build_logs":false,"activation":false},
  "volumes": null
}
```

Rules:

- **Capability honesty, both directions.** A declared capability must
  work; an undeclared operation must fail with the `unsupported` error
  kind (§7). Capabilities optimize failure timing; the error is still
  the enforcement.
- **The version-1 mask.** Native search/git/service passthrough, local
  shell commands, streamed stdin, and the effective-environment query do
  not cross the wire. A host forces `search.native`, `git.native`,
  `services.native`, `access.shell_command`, `exec.stdin_stream`, and
  `exec.environment` to false.
  `search.supported`, `git.supported`, and `services.supported` remain true when
  the complete facets can run through `exec/run`; the host then selects the
  exec-derived implementations.
- Older peers send `search`, `git`, and `services` groups as `{"native":false}`.
  Hosts read those groups as `supported:true` because `native:false` originally
  instructed the caller to use an exec-derived implementation. An explicitly
  sent `supported:false` means the complete facet is unavailable. An absent
  group also remains unsupported.
- The serialized `access.vpn` field is a compatibility tombstone. It is
  always false. VPN clients such as Tailscale are guest software managed
  through exec and are not a sandbox-driver capability.
- Version-1 peers can still send the legacy `lifecycle.checkpoint`,
  `snapshots.from_sandbox`, and `snapshots.include_memory` fields. Readers
  ignore them. New peers emit the normalized fields shown above.
- The aggregate snapshot source flags remain for version-1 compatibility.
  The `from_*_kinds` objects give exact container and virtual-machine
  support. If an exact flag is true, its aggregate flag must also be true.
- `capabilities.snapshots`/`volumes` being non-null is what authorizes
  the `snapshot/*` and `volume/*` methods (`snapshot/activate` and
  `snapshot/deactivate` additionally require `snapshots.activation`);
  `access.preview_urls` and `access.ssh` authorize the `access/*`
  methods.

## 6. Data conventions

- **Field names** are `snake_case`. Readers must ignore unknown object
  fields; new optional fields are the compatible evolution path.
- **Binary data** (file contents, command output, stdin) crosses as
  standard base64 with padding, in fields suffixed `_b64`.
- **Durations** appear in two forms, fixed per field: integer
  milliseconds in fields suffixed `_ms`, and the structural form
  `{"secs":90,"nanos":0}` where a spec object embeds one (e.g.
  `timers.auto_stop_after_idle`, `exec` spec timeouts inside
  `sandbox/create` are not applicable — exec uses `timeout_ms`). Both
  forms are covered by encoding tests; neither may change within
  version 1.
- **Timestamps** use the structural form
  `{"secs_since_epoch":…,"nanos_since_epoch":…}` where present
  (`created_at`, `expires_at`); they are informational.
- **Identifiers** (`sandbox_id`, `snapshot_id`, `volume_id`) are non-empty
  strings up to 256 bytes with no
  whitespace or control characters. They are opaque to the host and
  minted by the plugin; the host persists them to re-attach later.
- **State enums** are `snake_case` strings. A reader encountering an
  unknown state value must map it to `unknown`, not fail. Sandbox
  states: `creating starting running stopping stopped pausing paused
  resuming archiving archived restoring resizing forking snapshotting
  deleting deleted error unknown`. Snapshot states: `building active
  inactive error deleting unknown`. Volume states: `creating ready
  deleting deleted error unknown`.
- **Events and error kinds** likewise tolerate unknown values by
  ignoring the event or treating the kind as opaque.

## 7. Errors

Error codes: `-32600` malformed request or params, `-32601` unknown
method, `-32000` application failure. Application failures carry `data`:

```json
{
  "code": -32000,
  "message": "capability lifecycle.pause is not supported by this provider",
  "data": {
    "report": {"kind":"unsupported","message":"…","retryable":false,"causes":[]},
    "detail": {"capability":"lifecycle.pause"}
  }
}
```

`report.kind` is the stable machine-readable classification:
`not_found`, `unsupported`, `invalid_state`, `invalid_spec`, `timeout`,
`auth`, `rate_limited`, `exec`, `provider`, `transport`, `io`.
`report.causes` is a bounded rendered source chain. A receiver restores
these rendered causes as an opaque remote source chain. `detail` carries
kind-specific fields for faithful reconstruction:

| kind | detail fields |
| --- | --- |
| `unsupported` | `capability` (dotted path, e.g. `"exec.stdio_process"`) |
| `not_found` | `resource` (`sandbox`/`snapshot`/`volume`/`plugin`), `id` |
| `invalid_spec` | `field`, `reason` |
| `invalid_state` | `current`, `action` |
| `timeout` | `operation`, `elapsed` |
| `auth` | `auth` object: `{provider, reason}` |
| `rate_limited` | `retry_after` (optional) |
| `provider` | `provider` object: `{provider, code, message, retryable, detail}` |
| `exec` | `exec` object: `{label, termination, exit_code, stdout_b64, stderr_b64, duration_ms?}` (`duration_ms` is additive: senders may omit it, receivers must tolerate its absence) |
| `transport` | `transport_context` |
| `io` | `io_context` |

Raw command output appears only inside the `exec` detail — never in
`message` or `report`. Secret redaction is the host's responsibility.

## 8. Method catalog

All methods are host → plugin requests. `{}` denotes an empty result
object may be `null` — hosts must accept either for empty results.

### 8.1 Handles

Creation and attachment return a **HandleInfo**, everything a host needs
to operate a sandbox without further negotiation:

```json
{
  "status": {"id":"sb-1","name":"demo","state":"running","provider_state":"started",
              "error_reason":null,"resources":{"...":"…"},
              "sandbox_kind":"container","region":"eu","labels":{},
              "source":null,"workspace_ownership":null,
              "created_at":null,"updated_at":null},
  "capabilities": {"...":"per-sandbox set, §5"},
  "working_directory": "/workspace",
  "runtime_directory": null
}
```

| method | params | result |
| --- | --- | --- |
| `sandbox/create` | `{spec,events?}` — see §8.2 | HandleInfo |
| `sandbox/attach` | `{sandbox_id,events?}` | HandleInfo |
| `sandbox/list` | `{filter:{labels:{…}}}` | `{sandboxes:[status…]}` |
| `sandbox/describe` | `{sandbox_id}` | `{status}` |
| `sandbox/platform_info` | `{sandbox_id}` | `{platform:{os,arch,version}}` |

### 8.2 The creation spec

`spec` is an unvalidated DTO; the plugin validates and answers
`invalid_spec` for anything it cannot honor:

```json
{
  "name": null,
  "source": {"image":{"reference":"ubuntu:24.04"}},
  "resources": {"cpu_cores":null,"memory_mb":null,"disk_mb":null,"gpus":null},
  "sandbox_kind": "container",
  "env": {}, "labels": {}, "user": null,
  "working_directory": null,
  "network": "provider_default",
  "volumes": [], 
  "timers": {"auto_stop_after_idle":null,"auto_pause_after_idle":null,
              "auto_archive_after_stop":null,"auto_delete_after_stop":null,"ttl":null},
  "ephemeral": false, "public": null, "region": null,
  "provider_config": null
}
```

`source` variants: `{"image":{"reference":…}}`,
`{"dockerfile":{"content":…}}`, `{"snapshot":{"name":…}}`,
`"host_directory"`. `network` variants: `"provider_default"`,
`"allow_all"`, `"block"`, `{"cidr_allow_list":{"cidrs":[…]}}`,
`{"domain_allow_list":{"domains":[…]}}`. `provider_config` is an opaque
JSON value the plugin defines and documents.

`sandbox_kind` is nullable and accepts `"container"` or
`"virtual_machine"`. When set, it is a required result. The plugin must
honor it or return `invalid_spec`; it must not silently substitute a
different kind. This field is separate from `capabilities.isolation`.
The latter describes the provider's security boundary. The public Rust
API uses a typed `SnapshotId` for a snapshot source, but protocol version
1 retains the original `source.snapshot.name` field shown above.

Timer semantics: a `null` timer defers to the provider's default. A
**zero duration** (`{"secs":0,"nanos":0}`) is the explicit "never" — it
disables the timer where the provider supports disabling; the plugin
translates per timer (Daytona: wire `0` for auto-stop, `-1` for
auto-delete). The same rule applies to `sandbox/set_timers`.

`sandbox/create`, `sandbox/attach`, and `sandbox/undelete` accept an
optional `events` object:

```json
{"route_id":"event-7","correlation_id":"fabro-run-42"}
```

`route_id` is host-generated, unique per connection, and used only to
route `host/event` notifications to the correct observer. This works
before a provider assigns a resource ID. `correlation_id` is an optional
opaque application value copied into each emitted `Event`. Plugins must
not interpret either value. They must not contain secrets.

### 8.3 Lifecycle

All take `{sandbox_id}` and return `{}` unless noted. Optional verbs are
capability-gated (§5); `sandbox/delete` must be idempotent (deleting an
unknown or already-deleting sandbox succeeds). `sandbox/delete` is a
provider-level operation by id: it needs no prior `sandbox/attach`, so a
sandbox that no handle can be built for is still removed, and it accepts
the optional `events` object of §8.2.

`sandbox/start`, `sandbox/stop`, `sandbox/delete`, `sandbox/pause`,
`sandbox/resume`, `sandbox/archive`, `sandbox/recover`,
`sandbox/refresh_activity`.

`sandbox/recover` is provider-assisted recovery of a live sandbox from
the `error` state. `sandbox/undelete` (gated on `lifecycle.undelete`)
restores a **deleted** sandbox within the provider's recovery window and
returns a fresh HandleInfo — it addresses the provider, not a live
handle, because a deleted sandbox cannot be attached.

| method | params | result |
| --- | --- | --- |
| `sandbox/fork` | `{sandbox_id, options:{name,include_memory}}` | HandleInfo |
| `sandbox/undelete` | `{sandbox_id,events?}` | HandleInfo |
| `sandbox/resize` | `{sandbox_id, resources}` | `{}` |
| `sandbox/snapshot` | `{sandbox_id, options:{name,include_memory}}` | `{snapshot_id}` |
| `sandbox/set_timers` | `{sandbox_id, timers}` | `{}` |
| `sandbox/set_labels` | `{sandbox_id, labels:{…}}` | `{}` (full replace) |
| `sandbox/update_network` | `{sandbox_id, network}` | `{}` |

The core API has no optional-memory fork. A v1 adapter sends
`include_memory: true`; a v1 request with `false` fails as `invalid_spec`.
The source and returned sandbox must both be Running, and filesystem,
memory, running processes, and process IDs must be preserved.

For snapshots, `include_memory: false` maps to `Filesystem` and `true`
maps to `LiveProcessState`. Daytona requires a Stopped source for the
filesystem mode and a Running source for the live-process mode.

`sandbox/checkpoint` and `sandbox/restore_checkpoint` are reserved v1
tombstones. A server returns JSON-RPC `method not found`; the public API
does not expose these Boxd-only operations.

### 8.4 Exec

The exec contract: `program` and `args` are an **argument vector**, run
directly with `execvp` semantics. `program` is resolved through the
command's `PATH` when it contains no slash; every element of `args`
reaches the process unchanged. No shell is involved: nothing is split,
globbed, or expanded. A plugin whose backend takes a shell string must
quote the vector so it stays literal. Buffered and streaming execution
must not differ in how the vector is run.

A host that wants shell semantics sends them explicitly, as
`{"program":"bash","args":["-c","<script>"],"env":{"BASH_ENV":""}}` — the
`ExecSpec::bash` helper on the Rust side. The exec-derived facets and the
bash probe (§12) are sent that way, so a plugin's sandbox must have `bash`
on `PATH` to serve them.

The exec spec DTO:

```json
{"program":"echo","args":["hi"],"timeout_ms":30000,"working_dir":null,"env":{},"stdin_b64":null,"output_sanitization":"strip_ansi"}
```

`args` may be omitted and means `[]`.

`output_sanitization` is optional. Its values are `raw`, `strip_ansi`,
and `strip_all`; omission means `raw`. A plugin applies this policy to
buffered output and streaming notifications before capture accounting.
PTY and bidirectional stdio traffic always remains raw.

| method | params | result |
| --- | --- | --- |
| `exec/run` | `{sandbox_id, spec}` | ExecResult (below) |
| `exec/stream` | `{sandbox_id, exec_id, spec, retained_output_limit}` | ExecStreamResult (§9) |
| `exec/cancel` | `{exec_id}` | `{}` |
| `exec/stdio_open` | `{sandbox_id, process_id, spec}` | `{}` |
| `exec/stdio_input` | `{process_id, data_b64}` | `{}` |
| `exec/stdio_close_input` | `{process_id}` | `{}` |
| `exec/stdio_output` | `{process_id}` | `{data_b64:null | "…"}` |
| `exec/stdio_terminate` | `{process_id}` | `{}` |
| `exec/stdio_wait` | `{process_id}` | `{termination,exit_code,stderr_tail}` |
| `pty/open` | `{sandbox_id, pty_id, options}` | `{}` |
| `pty/input` | `{pty_id, data_b64}` | `{}` |
| `pty/output` | `{pty_id}` | `{data_b64:null | "…"}` |
| `pty/resize` | `{pty_id, size}` | `{}` |
| `pty/close` | `{pty_id}` | `{}` |
| `logs/follow` | `{sandbox_id, stream_id, source}` | `{}` after the stream ends |
| `stream/cancel` | `{stream_id}` | `{}` |

ExecResult:

```json
{"stdout_b64":"…","stderr_b64":"…","exit_code":0,"signal":null,
 "termination":"exited","duration_ms":12}
```

`signal` is additive: the signal number that ended the process when the
plugin observed one — on any termination, a foreign `kill` or the
plugin's own stop ladder alike — else absent or `null`; receivers
tolerate its absence. `termination` ∈ `exited timed_out cancelled killed unknown`. A timeout

or cancellation resolves the call **normally** with the corresponding
termination — it is not an error. `stdin_b64`, when present, is written
to the process then closed for EOF; a broken pipe while writing is not
an error.

`process_id`, `pty_id`, and `stream_id` are host-generated and unique
for the connection. Stdio and PTY reads are long-poll requests. The
server handles requests concurrently, so an output read never blocks
input, resize, terminate, or unrelated work — but a host must keep **at
most one outstanding output read per process or PTY id**: concurrent
reads on one id race their response ordering. `logs/follow` emits
`logs/output` notifications with `{stream_id,data_b64}` before its final
response. Dropping the host-side follow future sends `stream/cancel`.

### 8.5 Filesystem

Paths are sandbox-side strings; relative paths resolve against the
sandbox working directory.

| method | params | result |
| --- | --- | --- |
| `fs/read` | `{sandbox_id, path, offset?, length?}` | `{content_b64}` |
| `fs/write` | `{sandbox_id, path, content_b64, append?}` | `{}` (creates parents) |
| `fs/delete` | `{sandbox_id, path, recursive}` | `{}` |
| `fs/exists` | `{sandbox_id, path}` | `{exists}` |
| `fs/metadata` | `{sandbox_id, path}` | `{metadata:{kind,size,mode,modified_at}}` |
| `fs/list_dir` | `{sandbox_id, path, depth}` | `{entries:[{path,kind,size}…]}` |
| `fs/create_dir` | `{sandbox_id, path}` | `{}` |
| `fs/rename` | `{sandbox_id, from, to}` | `{}` |
| `fs/set_permissions` | `{sandbox_id, path, mode}` | `{}` (mode is numeric POSIX) |

`kind` ∈ `file directory symlink other`. `fs/read` takes an optional
byte `offset` (default `0`) and `length` (default: to end of file);
reading at or past the end returns empty content. `fs/write` takes an
optional `append` (default `false`) that appends instead of truncating,
creating the file when missing. Both fields were added within version 1;
readers ignore them when absent.

Upload/download have no wire methods: the host composes them from local
I/O plus `fs/read`/`fs/write` — in **bounded chunks** (the reference
implementation uses 4 MiB), using `offset`/`length` to page reads and
`append` to page writes, so a large file never crosses as a single
message buffered whole on both sides.

### 8.6 Snapshots and volumes

Available only when the corresponding capability object is non-null.
Deletes must be idempotent, including while deletion is in progress.

| method | params | result |
| --- | --- | --- |
| `snapshot/create` | `{spec:{name,source,sandbox_kind,region,resources,provider_config},events?}` | `{snapshot_id}` |
| `snapshot/get` | `{snapshot_id}` | `{status:{id,name,state,sandbox_kind,regions,resources,error_reason,size_bytes,created_at}}` |
| `snapshot/list` | `{filter:{name}}` | `{snapshots:[status…]}` |
| `snapshot/delete` | `{snapshot_id,events?}` | `{}` |
| `snapshot/activate` | `{snapshot_id,events?}` | `{}` (gated on `snapshots.activation`) |
| `snapshot/deactivate` | `{snapshot_id,events?}` | `{}` (gated on `snapshots.activation`) |
| `snapshot/build_logs` | `{snapshot_id, stream_id, follow}` | `{}` after the stream ends |
| `volume/create` | `{spec:{name,size_mb},events?}` | `{volume_id}` |
| `volume/get` | `{volume_id}` | `{status:{id,name,state,error_reason,created_at}}` |
| `volume/list` | `{}` | `{volumes:[status…]}` |
| `volume/delete` | `{volume_id,events?}` | `{}` |

Snapshot `source` variants: `{"image":{"reference":…}}`,
`{"dockerfile":{"content":…}}`,
`{"sandbox":{"id":…,"include_memory":…}}`.
The sandbox source uses the same v1 mapping: `false` is `Filesystem` and
`true` is `LiveProcessState`.
`sandbox_kind` and `region` are optional additive fields. A snapshot made
from a sandbox inherits its kind and resources; a conflicting request is
`invalid_spec`. Daytona supports image sources for both sandbox kinds and
Dockerfile sources for containers only.

### 8.7 Access

| method | params | result |
| --- | --- | --- |
| `access/preview_url` | `{sandbox_id, port}` | `{preview:{url,headers,expires_at}}` |
| `access/signed_preview_url` | `{sandbox_id, port, expires_in_ms}` | `{preview}` |
| `access/ssh_create` | `{sandbox_id, ttl_ms}` | `{access:{command,token,expires_at}}` |
| `access/ssh_revoke` | `{sandbox_id, token}` | `{}` |
| `access/web_terminal` | `{sandbox_id}` | `{url}` |
| `access/vnc` | `{sandbox_id}` | `{connection:{url,password}}` |

`access/ssh_create` returns a ready-to-run command. When `ttl_ms` is
absent, a provider may return stable access or use its default temporary
lifetime. When it is present, the provider must honor the requested TTL
or return `unsupported` for `access.ssh.ttl`. `token` and `expires_at`
are optional. `access/ssh_revoke` is available only when
`access.ssh.revoke` is true; a provider that declares it must return a
token that can be revoked.

### 8.8 Provider health

`provider/health` (params `{}`) reports whether the provider's backend
is reachable and its credential accepted, for host preflight and
diagnostics:

```json
{"health":{"status":"ok","message":null,"missing_permissions":[]}}
```

`status` ∈ `ok unreachable unauthorized unknown` (readers map unknown
values to `unknown`). `missing_permissions` names credential scopes the
provider knows are absent (e.g. Daytona API-key scopes). An unhealthy
provider is a **successful** response with a non-`ok` status — errors
are reserved for failures of the check itself. Hosts must treat a
`-32601` reply (a plugin predating this method) as
`{"status":"unknown"}`.

### 8.9 Shutdown

`shutdown` (params `{}`) asks the plugin to exit. The plugin must answer
the request, then stop reading and exit promptly. A plugin must also
exit when its stdin reaches EOF. Hosts should reap the process and may
kill it after a grace period.

## 9. Streaming exec

`exec/stream` is the one method with mid-flight traffic:

```
host → {"id":7,"method":"exec/stream","params":{"sandbox_id":"sb-1","exec_id":"x1",
         "spec":{"program":"cargo","args":["build"],"timeout_ms":null,…},"retained_output_limit":65536}}
plugin → {"method":"exec/output","params":{"exec_id":"x1","stream":"stdout","data_b64":"…"}}
plugin → {"method":"exec/output","params":{"exec_id":"x1","stream":"stderr","data_b64":"…"}}
host → {"id":8,"method":"exec/cancel","params":{"exec_id":"x1"}}          (optional)
plugin → {"id":8,"result":{}}
plugin → {"id":7,"result":{"result":{…,"termination":"cancelled"},
           "streams_separated":true,"live_streaming":true,
           "stdout_capture":{"observed_bytes":…,"retained_bytes":…,"omitted_bytes":…,
                             "truncated":false},
           "stderr_capture":{…}}}
```

Rules:

- `exec_id` is **host-generated** and unique per connection, so output
  can be routed and cancellation addressed before the `exec/stream`
  response exists.
- Every `exec/output` for an exec must be sent **before** its
  `exec/stream` response, in the order the output was observed.
  `stream` ∈ `stdout stderr`.
- **Honesty flags.** `live_streaming` is true only if output was
  delivered while the command ran (a plugin that buffers and replays
  must say false). `streams_separated` is true only if stdout and
  stderr are genuinely distinct (combined-output backends must say
  false and use `stdout`). Results must never claim a flag the
  `initialize` capabilities did not declare.
- **Retention.** `retained_output_limit` bounds only the buffered copy
  returned in the result (a stable head plus rolling tail); the full
  stream must still be drained and emitted as notifications, with
  accounting such that `retained + omitted = observed` per stream.
  `truncated` (optional, default `false`; added within v1) means bytes
  were lost *beyond* that accounting — the provider abandoned an
  unfinished drain — so the counts undercount the real output.
- **Backpressure and isolation.** A plugin must not buffer output
  unboundedly: when the transport cannot keep up, it must stall the
  producing process (pipe backpressure), never drop output. Both sides
  must keep one slow stream from starving unrelated traffic: a slow
  consumer of one exec's output must not delay another exec's output or
  any response beyond transient, bounded queuing. The conformance
  suite's `concurrent_streams_do_not_starve_each_other` check is the
  acceptance test.
- `exec/cancel` for an unknown or finished `exec_id` succeeds and does
  nothing.

## 10. Events

The plugin emits `host/event` notifications for sandbox, snapshot, and
volume control-plane operations. Exec output, PTY bytes, file-transfer
chunks, and logs use their dedicated streams and never use this event
feed.

```json
{"method":"host/event","params":{
  "route_id":"event-7",
  "event":{
    "id":{"source_id":"9b2f…","sequence":4},
    "occurred_at":{"secs_since_epoch":1788206400,"nanos_since_epoch":0},
    "provider":"daytona",
    "subject":{"type":"sandbox","id":"sb-1"},
    "operation_id":"58a1…",
    "correlation_id":"fabro-run-42",
    "type":"operation_failed",
    "action":"start",
    "duration":{"secs":30,"nanos":0},
    "error":{"kind":"timeout","message":"…","retryable":true,"causes":[]}
  }
}}
```

The event envelope fields are:

- `id`: `{source_id,sequence}`. `source_id` identifies one live event
  source. `sequence` starts at 1 and increases by one for that source.
- `occurred_at`: the observation time in the structural timestamp form
  from §6.
- `provider`: the provider kind.
- `subject`: `{"type":"provider"}` or a `sandbox`, `snapshot`, or
  `volume` subject. Resource subjects carry an optional `id` and `name`.
- `operation_id`: present on operation lifecycle events. It is stable
  from start through terminal outcome.
- `correlation_id`: the optional consumer value from the `events`
  request object.
- `type` and its body fields.

Event `type` values are:

- `operation_started` with `action`.
- `operation_progress` with `action` and `progress`. Progress has a
  stable `code`, an optional display `message`, and optional
  `completed`, `total`, and `unit` measurements. Consumers must branch
  on `code`, not `message`.
- `operation_completed` with `action` and `duration`.
- `operation_failed` with `action`, `duration`, and the structured error
  report from §7.
- `state_observed` with optional `previous` and required `current`
  resource state.
- `notice` with a stable `code` and display `message`.

For each accepted operation, the plugin must emit
`operation_started` and exactly one `operation_completed` or
`operation_failed`. They must have the same `operation_id`. The terminal
event must enter the wire before the operation response. A create can
start with a name-only subject. Its terminal event must include the
provider-assigned resource ID when one was assigned.

Delivery is ordered and lossless at the sandbox-driver handoff. A
sender must await bounded transport capacity and must not silently drop
events. The receiver must observe event notifications in wire order
before it resolves the corresponding operation response. `route_id` is
optional in a notification and echoes the request value when present;
it is transport metadata, not event identity.

The protocol has no event replay or persistence API. The host decides
whether its observer persists events. `sandbox/describe`,
`snapshot/get`, and `volume/get` remain authoritative for current
resource state. A re-attach creates a new live event source. Unknown
event types and subject kinds must be ignored without closing the
connection.

`host/log` (`{level, message}`) is reserved: plugins should prefer
stderr for logs in version 1, and hosts may ignore `host/log`.

## 11. Discovery and trust (host-side conventions)

These bind hosts that launch plugins from configuration; the reference
implementation is `sandbox_driver_protocol::discovery`.

- **Naming convention.** A plugin binary is found either at an
  explicitly configured path or as `<prefix>-<kind>` on `PATH`, where
  `<prefix>` is chosen by the embedder (fabro uses `fabro-sandbox`,
  giving `fabro-sandbox-e2b`). There is no other fallback; unknown kinds
  are never launched (deny by default).
- **Checksum or dev, never neither.** Configuration pins the binary's
  SHA-256, verified before exec; a mismatch is a hard failure naming
  both hashes. Launching without a pin requires an explicit dev flag,
  and such launches are reported as unverified so operators can be
  warned.
- **Environment scrubbing.** The plugin starts from an empty
  environment plus exactly the variables its configuration declares or
  explicitly forwards. Provider credentials should be passed this way
  deliberately, never inherited.
- **Identity check.** After `initialize`, a declared `provider.kind`
  differing from the configured kind must abort the plugin.
- A plugin is inside the trust domain of every sandbox it drives; see
  the security section of the interface design document.

## 12. Conformance

A plugin is conformant when the `sandbox-driver-conformance` suite
passes against it through `PluginProvider` — the same battery every
in-process provider must pass, covering lifecycle, the bash probe,
exec semantics (literal argv, exit codes, env, binary safety, stdin,
timeout, cancellation), streaming honesty and isolation, retention accounting,
filesystem round trips, capability honesty in both directions, label
listing, event delivery, and service/facet-capability consistency.

## 13. Compatibility policy

Within version 1: changes must be additive (new methods, new optional
fields, new enum values that readers already tolerate). Anything else —
renaming fields, changing a pinned encoding, making an optional field
required — requires incrementing `protocol_version`, and the handshake's
version check is the only compatibility gate. Compatibility is verified
behaviorally: readers must decode era JSON written before any later
additive field existed (every wire struct's growable fields carry serde
defaults), tolerate unknown fields and enum values, and keep the pinned
per-field encodings. Full-shape golden pins are deliberately not used —
they fail on additive changes this section declares compatible.

## 14. Deferred beyond version 1

Native search/git/service passthrough, local `shell_command`, and
`host/credentials` (per-call secret fetches from the host) remain
deferred. They are masked or absent in version 1 per §5.
