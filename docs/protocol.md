# sandbox-driver plugin protocol, version 1

This is the normative specification of the wire protocol between a
**host** (an application embedding `sandbox-driver`, such as fabro) and a
**plugin** (an executable serving one sandbox provider). It is written so
a plugin can be implemented in any language without reading the Rust
source. The Rust implementation lives in the `sandbox-driver-protocol`
crate: `serve_stdio()` is the plugin side, `PluginProvider` the host
side, and the golden tests in `crates/sandbox-driver-protocol/tests/`
pin every serialized shape shown here.

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
  "lifecycle": {"pause":false,"archive":false,"fork":false,"checkpoint":false,
                 "resize":false,"recover":false,"refresh_activity":false,
                 "timers":false,"labels":false,"update_network":false,
                 "snapshot_sandbox":false},
  "exec": {"live_streaming":false,"streams_separated":false,"stdin":false,
            "cancel":false,"stdio_process":false},
  "fs": {"native":false,"upload":false,"download":false,"permissions":false},
  "search": {"native":false},
  "git": {"native":false},
  "pty": null,
  "logs": null,
  "access": {"preview_urls":false,"signed_preview_urls":false,"ssh":false,
              "shell_command":false,"web_terminal":false,"vnc":false,"vpn":false},
  "network": {"allow_all":false,"block_all":false,"cidr_allow_list":false,
               "domain_allow_list":false,"outbound_proxy":false},
  "snapshots": null,
  "volumes": null
}
```

Rules:

- **Capability honesty, both directions.** A declared capability must
  work; an undeclared operation must fail with the `unsupported` error
  kind (§7). Capabilities optimize failure timing; the error is still
  the enforcement.
- **The version-1 mask.** The wire cannot carry long-lived stdio
  processes, PTY, provider logs, or native search/git passthrough, and
  the `shell_command`, `web_terminal`, `vnc`, and `vpn` access facets
  are reserved. A host must treat these as absent regardless of what the
  plugin declares: force `exec.stdio_process` to false, `pty` and `logs`
  to null, `search.native` and `git.native` to false, and the four
  reserved access booleans to false. A plugin should not declare them.
- `capabilities.snapshots`/`volumes` being non-null is what authorizes
  the `snapshot/*` and `volume/*` methods; `access.preview_urls` and
  `access.ssh` authorize the `access/*` methods.

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
  forms are pinned by golden tests; neither may change within version 1.
- **Timestamps** use the structural form
  `{"secs_since_epoch":…,"nanos_since_epoch":…}` where present
  (`created_at`, `expires_at`); they are informational.
- **Identifiers** (`sandbox_id`, `snapshot_id`, `volume_id`,
  `checkpoint_id`) are non-empty strings up to 256 bytes with no
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
`auth`, `rate_limited`, `exec`, `provider`, `io`. `report.causes` is a
bounded rendered source chain. `detail` carries kind-specific fields for
faithful reconstruction:

| kind | detail fields |
| --- | --- |
| `unsupported` | `capability` (dotted path, e.g. `"exec.stdio_process"`) |
| `not_found` | `resource` (`sandbox`/`snapshot`/`volume`/`checkpoint`/`plugin`), `id` |
| `invalid_spec` | `field`, `reason` |
| `provider` | `provider` object: `{provider, code, message, retryable, detail}` |
| `exec` | `exec` object: `{label, termination, exit_code, stdout_b64, stderr_b64}` |

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
  "status": {"id":"sb-1","state":"running","provider_state":"started",
              "error_reason":null,"resources":{"...":"…"},"labels":{},
              "source":null,"workspace_ownership":null,
              "created_at":null,"updated_at":null},
  "capabilities": {"...":"per-sandbox set, §5"},
  "working_directory": "/workspace",
  "runtime_directory": null
}
```

| method | params | result |
| --- | --- | --- |
| `sandbox/create` | `{spec}` — see §8.2 | HandleInfo |
| `sandbox/attach` | `{sandbox_id}` | HandleInfo |
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

### 8.3 Lifecycle

All take `{sandbox_id}` and return `{}` unless noted. Optional verbs are
capability-gated (§5); `sandbox/delete` must be idempotent (deleting an
unknown or already-deleting sandbox succeeds).

`sandbox/start`, `sandbox/stop`, `sandbox/delete`, `sandbox/pause`,
`sandbox/resume`, `sandbox/archive`, `sandbox/recover`,
`sandbox/refresh_activity`.

| method | params | result |
| --- | --- | --- |
| `sandbox/fork` | `{sandbox_id, options:{name,include_memory}}` | HandleInfo |
| `sandbox/checkpoint` | `{sandbox_id, options:{name}}` | `{checkpoint_id}` |
| `sandbox/restore_checkpoint` | `{sandbox_id, checkpoint_id}` | `{}` |
| `sandbox/resize` | `{sandbox_id, resources}` | `{}` |
| `sandbox/snapshot` | `{sandbox_id, options:{name,include_memory}}` | `{snapshot_id}` |
| `sandbox/set_timers` | `{sandbox_id, timers}` | `{}` |
| `sandbox/set_labels` | `{sandbox_id, labels:{…}}` | `{}` (full replace) |
| `sandbox/update_network` | `{sandbox_id, network}` | `{}` |

### 8.4 Exec

The command contract: `command` is **Bash source**, run as
`bash -c <command>`, non-login, no `errexit`/`pipefail`/POSIX mode,
never a fallback to `sh`, `BASH_ENV` stripped. Buffered and streaming
execution must not differ in interpreter or options.

The exec spec DTO:

```json
{"command":"echo hi","timeout_ms":30000,"working_dir":null,"env":{},"stdin_b64":null}
```

| method | params | result |
| --- | --- | --- |
| `exec/run` | `{sandbox_id, spec}` | ExecResult (below) |
| `exec/stream` | `{sandbox_id, exec_id, spec, retained_output_limit}` | ExecStreamResult (§9) |
| `exec/cancel` | `{exec_id}` | `{}` |

ExecResult:

```json
{"stdout_b64":"…","stderr_b64":"…","exit_code":0,
 "termination":"exited","duration_ms":12}
```

`termination` ∈ `exited timed_out cancelled killed unknown`. A timeout
or cancellation resolves the call **normally** with the corresponding
termination — it is not an error. `stdin_b64`, when present, is written
to the process then closed for EOF; a broken pipe while writing is not
an error.

### 8.5 Filesystem

Paths are sandbox-side strings; relative paths resolve against the
sandbox working directory.

| method | params | result |
| --- | --- | --- |
| `fs/read` | `{sandbox_id, path}` | `{content_b64}` |
| `fs/write` | `{sandbox_id, path, content_b64}` | `{}` (creates parents) |
| `fs/delete` | `{sandbox_id, path, recursive}` | `{}` |
| `fs/exists` | `{sandbox_id, path}` | `{exists}` |
| `fs/metadata` | `{sandbox_id, path}` | `{metadata:{kind,size,mode,modified_at}}` |
| `fs/list_dir` | `{sandbox_id, path, depth}` | `{entries:[{path,kind,size}…]}` |
| `fs/create_dir` | `{sandbox_id, path}` | `{}` |
| `fs/rename` | `{sandbox_id, from, to}` | `{}` |
| `fs/set_permissions` | `{sandbox_id, path, mode}` | `{}` (mode is numeric POSIX) |

`kind` ∈ `file directory symlink other`. Upload/download have no wire
methods: the host composes them from local I/O plus `fs/read`/`fs/write`.

### 8.6 Snapshots and volumes

Available only when the corresponding capability object is non-null.
Deletes must be idempotent, including while deletion is in progress.

| method | params | result |
| --- | --- | --- |
| `snapshot/create` | `{spec:{name,source,resources,provider_config}}` | `{snapshot_id}` |
| `snapshot/get` | `{snapshot_id}` | `{status:{id,name,state,error_reason,size_bytes,created_at}}` |
| `snapshot/list` | `{filter:{name}}` | `{snapshots:[status…]}` |
| `snapshot/delete` | `{snapshot_id}` | `{}` |
| `volume/create` | `{spec:{name,size_mb}}` | `{volume_id}` |
| `volume/get` | `{volume_id}` | `{status:{id,name,state,error_reason,created_at}}` |
| `volume/list` | `{}` | `{volumes:[status…]}` |
| `volume/delete` | `{volume_id}` | `{}` |

Snapshot `source` variants: `{"image":{"reference":…}}`,
`{"dockerfile":{"content":…}}`,
`{"sandbox":{"id":…,"include_memory":…}}`.

### 8.7 Access

| method | params | result |
| --- | --- | --- |
| `access/preview_url` | `{sandbox_id, port}` | `{preview:{url,headers,expires_at}}` |
| `access/signed_preview_url` | `{sandbox_id, port, expires_in_ms}` | `{preview}` |
| `access/ssh_create` | `{sandbox_id, ttl_ms}` | `{access:{command,token,expires_at}}` |
| `access/ssh_revoke` | `{sandbox_id, token}` | `{}` |

### 8.8 Shutdown

`shutdown` (params `{}`) asks the plugin to exit. The plugin must answer
the request, then stop reading and exit promptly. A plugin must also
exit when its stdin reaches EOF. Hosts should reap the process and may
kill it after a grace period.

## 9. Streaming exec

`exec/stream` is the one method with mid-flight traffic:

```
host → {"id":7,"method":"exec/stream","params":{"sandbox_id":"sb-1","exec_id":"x1",
         "spec":{"command":"cargo build","timeout_ms":null,…},"retained_output_limit":65536}}
plugin → {"method":"exec/output","params":{"exec_id":"x1","stream":"stdout","data_b64":"…"}}
plugin → {"method":"exec/output","params":{"exec_id":"x1","stream":"stderr","data_b64":"…"}}
host → {"id":8,"method":"exec/cancel","params":{"exec_id":"x1"}}          (optional)
plugin → {"id":8,"result":{}}
plugin → {"id":7,"result":{"result":{…,"termination":"cancelled"},
           "streams_separated":true,"live_streaming":true,
           "stdout_capture":{"observed_bytes":…,"retained_bytes":…,"omitted_bytes":…},
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

The plugin may emit `host/event` notifications carrying sandbox
progress:

```json
{"method":"host/event","params":{"sandbox_id":"sb-1",
  "event":{"type":"action_failed","action":"start",
            "error":{"kind":"timeout","message":"…","retryable":true,"causes":[]}}}}
```

Event `type`s: `action_started`, `action_completed` (+`duration`),
`action_failed` (+`error` report), `snapshot_building`, `snapshot_ready`,
`snapshot_failed`, `state_changed` (`from`/`to`), `progress`
(+`message`). Delivery is best-effort and in-order per sandbox; there
is no replay — durable state is `sandbox/describe`. Terminal events
(`action_completed`, `action_failed`, `snapshot_ready`,
`snapshot_failed`) should never be dropped by either side. Events
emitted during `sandbox/create`, before an id exists, may carry an empty
`sandbox_id`; hosts may ignore those.

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
in-process provider must pass, covering lifecycle, the Bash contract,
exec semantics (exit codes, env, binary safety, stdin, timeout,
cancellation), streaming honesty and isolation, retention accounting,
filesystem round trips, capability honesty in both directions, label
listing, event delivery, and service/facet-capability consistency.

## 13. Compatibility policy

Within version 1: changes must be additive (new methods, new optional
fields, new enum values that readers already tolerate). Anything else —
renaming fields, changing a pinned encoding, making an optional field
required — requires incrementing `protocol_version`, and the handshake's
version check is the only compatibility gate. The golden tests are the
change detector: a golden-test failure is a wire break to be redesigned,
not re-pinned.

## 14. Deferred beyond version 1

Long-lived bidirectional stdio (`exec.stdio_process`) and its
side-channel transport; PTY; provider log streaming; native search/git
passthrough; the `shell_command`, `web_terminal`, `vnc`, and `vpn`
access facets; snapshot build-log streaming; and `host/credentials`
(per-call secret fetches from the host). All are masked or absent in
version 1 per §5.
