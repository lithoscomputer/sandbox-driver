# Docker lifecycle coordination

The Docker provider serializes resource creation, command admission, one-shot
admission, and lifecycle mutations through a daemon-scoped claim. Independent
provider instances that connect to the same daemon use the same claim. This is
the stop fence behind the `access: shared` that `DockerFactory`'s provider
reports.

The claim is an unstarted container with a unique Docker name. It carries
`sh.sandbox-driver.fence` and `sh.sandbox-driver.fence-operation` labels and is
excluded from sandbox inventory. Creation acquires a claim before exposing the
primary container; its `sh.sandbox-driver.fence` label is the requested sandbox
name, so deleting that name finds the claim before the primary exists. The
primary's `sh.sandbox-driver.fence-name` label records
that claim name for subsequent clients. Older sandboxes without this label use
the canonical container ID to identify their claim.

Lifecycle and admission claims also record the primary's Docker name in
`sh.sandbox-driver.fence-sandbox-name`. If the primary disappears before claim
release, retries by name, full ID, or short ID still report `busy`. Discovery
lists claims and matches their preserved identities; unrelated names remain
absent. Claims created by older versions without the name label must be
reconciled using their recorded identifier when the primary is already gone.

An admitted exec releases its claim after Docker starts the attached execution;
the command itself can then run concurrently with other commands. One-shots
release admission after their container has started and carry the sandbox ID
for later discovery. Image preparation precedes one-shot admission. A prepared
one-shot must still acquire the claim and observe a running sandbox before it
can start.

Stop holds the claim while removing one-shots, stopping the primary container,
and stopping its services. It inspects the primary and services to confirm they
are no longer running; missing or still-running state returns `fence_leaked`
and retains the claim. Start, exec, one-shot admission and destroy cannot
overtake that drain. A competing lifecycle claim is refused with `Busy`. Any
operation waits up to five seconds behind a held admission claim, since admissions release quickly; a held
lifecycle claim refuses it at once. Describe and inventory remain
available while a claim is held, and so do the stop-request and PTY cleanup
execs that end already-admitted commands: they start no new work, so a held
claim must not keep a command from being stopped.

## Failure and reconciliation

A completed daemon refusal releases the claim so the application can decide
whether to retry. A transport failure, deadline, or dropped caller retains it:
the provider cannot establish that the remote mutation finished. There is no
lease expiry, automatic takeover, or mutation replay. The caller receives
`Transport` with outcome `unknown`. A cancelled future cannot return an error,
so the labels provide the reconciliation record.

Inside the provider, these failures are old-API `ProviderError`s whose codes
(`busy`, `fence_leaked`, `transport`, `incomplete_cleanup`) and structured
`detail` the paragraphs below name. That error type is in the
`sandbox_driver::legacy` module, which is being removed. The `Sandboxes` API
maps it to `Busy`, `FenceLeaked`, `Transport` with an unknown outcome, and
`IncompleteCleanup` with the `remaining` resources, including a retained claim
as a `fence_container` resource. Other detail fields reach the caller only as
diagnostic text.

HTTP 502 and 504 responses also retain ownership. A gateway can return these
after forwarding a mutation, without establishing the daemon's outcome. This
applies to claim acquisition as well as operations inside an acquired claim;
neither is replayed automatically.

Internally, operation failures carry a typed claim disposition separately from
their diagnostic error. Combining primary/service or creation/cleanup outcomes
retains any requirement for reconciliation before choosing the public error.
The selected diagnostic cannot turn an unresolved operation into a releasable
claim.

If claim release fails, `detail.operation_outcome` distinguishes completed work
from failed work. `operation_error` and `release_error` preserve both reports,
including provider codes and structured details. `sandbox` records the operation's
target; a completed creation also records its actual `sandbox_id`, so a release
failure does not discard the new resource's identity. Success is still withheld
until release is confirmed.

One-shot admission keeps its partial container and cleanup-attempt state until
the claim outcome is known. An attach/start failure combined with uncertain
cleanup retains ownership and both diagnostics; admission does not retry a
cleanup request whose outcome is unknown.

The claim must not be removed merely because its creator disconnected or a
period of time passed. An operator or application recovery procedure must first
establish that the original request can no longer change the sandbox and that
any required termination or cleanup is complete. Then it removes the claim named
as the error's `fence_container` with `docker rm <fence_container>`. Claims are
unstarted containers, so `docker container prune` and `docker system prune`
remove held and retained claims without any check; do not prune a daemon that
has managed sandboxes in use. Different clients, including
older provider versions and direct Docker commands, must not bypass this
coordination while managed work is active. The mechanism coordinates cooperating
provider clients; it is not an authorization boundary against Docker admins.

Each daemon call that acquires, discovers, or releases a claim has a 60-second
bound. Execution admission, stop and destroy have a 60-second operation
bound; create and start have a six-minute bound to allow the service readiness
budget. Create pulls the primary and service images before it takes
the claim. Under the claim, the work after the primary exists is bounded to five
minutes, and a timeout runs the same failed-create cleanup as any other creation
failure. Services are started together and share one five-minute readiness
deadline, on create and on start. A failure to confirm claim release is an error
even if the workload mutation completed.

A failed create attempts dependent cleanup before removing the primary, with a
30-second cleanup budget. Unconfirmed cleanup uses `incomplete_cleanup` and
serializes the `IncompleteCleanup` error in `detail`, including
resource identifiers whose removal remains unconfirmed, plus the original
creation failure as an error report under `cause` and the cleanup failure under
`cleanup_cause`. A transport failure during either creation or cleanup retains
the claim and includes it in the remaining resources, even if the other failure
was a completed daemon refusal. Creation failures whose cleanup succeeds
preserve their original error.

## The provider

`sandbox_driver_docker::DockerFactory` registers Docker as a built-in with a
`sandbox_driver::Registry`. An entry's only `config` key is `host` (`unix://`,
`tcp://` or `http://`; default `unix:///var/run/docker.sock`); nothing is read
from the ambient environment.

The descriptor reports the namespace `docker:<engine ID>` (stable across daemon
restarts, different per daemon), `durability: machine`, `access: shared`, image
sources, cpu and memory, the `allow_all` and `block` network modes, every
`container` field, services, one-shot containers, and the shell-command
endpoint. No timers are enforced, so any timer request is `Unsupported`, as are
disk, GPUs, other sources and allow-list networks. `start` on a container the
daemon paused out of band unpauses it, so its processes carry on.

- **Services** become sidecars on the workload's network, reachable by their
  service name. A readiness check runs as an exec-form Docker health check in
  the service, with its own deadline (at most five minutes), on create and
  again on start. Docker runs the first check one interval after the service
  starts, so `interval_ms` must be shorter than `deadline_ms`. A service
  without a check is only confirmed started, and its image's own
  `HEALTHCHECK` is turned off. `status.services` lists only services running
  now. A service `credential` names a secret whose value is a JSON object with
  `username`, `password` and an optional `server`.
- **`provider_config`** takes `auto_pull`, `platform`, `binds` and
  `host_network`, described by the descriptor's `spec_schema`. `binds` is
  refused unless the daemon is local (`unix://`), matching the descriptor's
  `mounts_host_paths`.
- **Labels** under `sh.sandbox-driver.` are reserved. Docker merges an image's
  own labels into the container's, so the caller's keys are recorded in
  `sh.sandbox-driver.labels` and only those are reported by `status` and
  `list` or matched by a label filter. Sandboxes created before that label
  existed report every label the provider did not write.
- **Exec** runs argv without a shell; `tty` is unsupported. A command on a
  sandbox that is not running is refused, never reported as an outcome. A
  command that loses its stream reports `killed` only once its container run
  is confirmed ended: at once if the run changed, or after waiting up to ten
  seconds while a stop or destroy holds the claim; otherwise the transport
  error is returned. `files.list` uses POSIX `sh` and `find`, so it needs no
  `bash`; a directory that exists but cannot be read fails the listing
  instead of reporting `NotFound`.
- **Ports** are exposed as unsigned local forwards without a TTL; signed or
  expiring exposure is `Unsupported`.
- **Errors:** a daemon 404 maps to `NotFound` only when the primary is gone;
  a missing image or service is `Unhealthy`, so callers do not treat the
  sandbox as removed.
- **Reconciliation:** sidecars and their network carry
  `sh.sandbox-driver.sandbox=<full sandbox ID>`. Destroying a sandbox whose
  primary is already gone removes them by that label before reporting success.
  Inventory reports neither sidecars nor one-shots as sandboxes.

## Verification

Run the Docker verification path against a real daemon:

```sh
mise run test:docker
```

An unreachable daemon fails this task instead of silently skipping live
coverage. It runs the provider's tests (`--test provider`): the shared
conformance suite, with a second activated catalog for the cross-instance
fence; services and one-shots sharing the workload; label round-trip and exec
on a stopped sandbox; start after an out-of-band pause; refusal before
admission; and reconciliation of a vanished primary. It runs the same provider
over protocol 3 as the `test-docker` fixture plugin, the live fence and
lifecycle failure-injection tests, and the old API's conformance suite
(`--test conformance`). It also runs the `lithos-sandbox` CLI workflow, with
the Docker provider linked into the CLI.

To run only the real-daemon fence tests:

```sh
cargo test --locked -p sandbox-driver-docker --test fence -- --ignored
```

They exercise independent provider clients, stop versus exec, one-shots and
services, start during draining, cancelled ownership, and attachment during
creation. The lifecycle failure-injection tests cover release failure,
uncertain admission, retained ownership after primary removal, and incomplete
creation cleanup. These files and `--test conformance` still drive the old
provider API, and one fence
case runs two `sandbox-driver-docker` executables over protocol 2; they are
being ported or removed with it.

For a direct manual CLI check after `mise run dev`:

```sh
sb=$(target/debug/lithos-sandbox create docker \
  --image ghcr.io/lithoscomputer/ubuntu-24.04:slim-df708f910111)
target/debug/lithos-sandbox exec "$sb" -- uname -a
target/debug/lithos-sandbox stop "$sb"
target/debug/lithos-sandbox start "$sb"
target/debug/lithos-sandbox destroy "$sb"
```
