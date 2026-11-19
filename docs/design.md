# sandbox-driver design

> **Status:** This is the specification of the `Sandboxes` API that the
> `sandbox_driver` crate root exports, and of what every provider behind it
> must guarantee. It changes in the same PR as the code. Host, Docker and
> Daytona implement it as built-ins, and protocol version 3 loads third-party
> plugins. The
> [README](https://github.com/lithoscomputer/sandbox-driver/blob/main/README.md)
> introduces the API with runnable in-memory examples.
>
> Still in the tree but being removed: the old provider API in the hidden
> `sandbox_driver::legacy` module, protocol version 2, the Host, Docker and
> Daytona provider executables, and the `sandbox-driver-docker-config` and
> `sandbox-driver-daytona-config` crates. If you need them, pin tag
> [`v2`](https://github.com/lithoscomputer/sandbox-driver/tree/v2).

One interface to any sandbox. Clients name an environment; providers own the sandboxes; the library owns everything in between.

```rust
// Shared by requests within the Fabro server process.
// Worker processes construct their own instance from resolved configuration.
let sandboxes = Sandboxes::try_new(
    settings.sandbox.providers.clone(), environments, &registry, secrets,
    CatalogOptions::default(),
)?;

// A run starts on the "cloud" environment.
let sandbox = sandboxes.builder("cloud").await?             // seeded from the environment's template
    .label("fabro.run", &run.id)
    .create()
    .await?;

sandbox.exec(ExecSpec::argv(["git", "clone", &repo, "."]), ExecControls::default()).await?;
run.sandbox_ref = Some(sandbox.reference());         // {provider, namespace, id}, stored with the run

// Later, from the sandbox page in another request.
let sandbox = sandboxes.attach(&run.sandbox_ref).await?;
let port = NonZeroU16::new(3000).unwrap();
let exposure = sandbox.ports().expose(port, Expose { signed: true, ttl_ms: Some(3_600_000) }).await?;

// Everything this run created, across every provider.
let leftovers = sandboxes.find(LabelFilter::eq("fabro.run", &run.id)).await?;
```

`"cloud"` is an **environment**: a named template on a **provider entry**. The entry says how to reach a backend; the environment says what to build on it. Many environments share one entry.

```toml
[providers.daytona]                      # a connection, named by the operator
plugin  = "daytona"                      # built in
config  = { api_url = "https://app.daytona.io/api", organization = "org_…" }
secrets = ["DAYTONA_API_KEY"]

[environments.cloud]
provider = "daytona"

[environments.cloud.spec]
source    = { dockerfile = "FROM buildpack-deps:noble\n" }   # or { image = "buildpack-deps:noble" }
resources = { cpu = 2, memory = "4GB" }
network   = { mode = "allow_all" }
timers    = { auto_stop = "60m" }
```

Fabro keeps provider entries in its server settings and environments in its database, edited in the UI. A workflow selects one with `[run.environment] id = "cloud"`, and says what happens to the sandbox when the run ends with `[run.lifecycle]`, which is Fabro's policy and not part of the environment. The values above are Fabro's seeded default for Daytona; a workflow that needs more, like Fabro's own code review, gives a longer Dockerfile that installs its tools on the same base. The Daytona provider builds the source into a Daytona snapshot named by its inputs and reuses it on later runs. The library itself ships no provider entries or environments.

Everything in the template rides along on `create()`. A caller that needs something different for one sandbox overrides it on the builder, and the provider validates the override against what it supports:

```rust
let sandbox = sandboxes.builder("cloud").await?.memory("8GB").create().await?;
```

Clients pass the environment name and never the provider's. Whether `cloud` points at the built-in Daytona provider, the built-in Docker one, or a plugin someone wrote last week, the code above is the same.

## What it is

- A **client API**: one `Sandboxes` value built once, a sandbox builder, and the `Sandbox` trait. That is all an embedding program sees.
- A **provider interface**: the `ProviderFactory` and `Provider` traits a built-in implements in Rust, and the same calls carried over protocol version 3 for a plugin in another process. A provider owns all state for its sandboxes; the library stores only refs.
- A **catalog** in two levels: provider entries (which provider, its connection, its trust settings) and environments (a named spec template on an entry). The client decides where each level is stored and whether it changes at runtime; the library defines what an entry means.
- Everything **between them**: discovery, trust, supervision, restart, identity, admission checks, a fake for tests, and a conformance suite for provider authors.

The library provisions and operates sandboxes. Scheduling, queueing, lease management and run-end policy belong to the caller.

## Concepts

| Term | Meaning |
| --- | --- |
| **Provider** | A backend that makes sandboxes. Built in (`host`, `docker`, `daytona`) or a plugin. |
| **Provider entry** | A named, configured connection to a provider: which provider, its config, the secrets it needs, and for a plugin its path and trust. Operator-owned. One entry serves many environments; two entries can use the same provider (a production and a staging Daytona org). |
| **Environment** | A named spec template on a provider entry: source, resources, network, timers, labels, env, working directory. User-owned. What clients and workflows name. |
| **Built-in** | `host`, `docker` and `daytona`. Library code the application registers with `Registry::builtin`; it runs in the application's process. |
| **Plugin** | Any other provider: an executable speaking protocol version 3, run as a supervised child process. Clients cannot tell it from a built-in. |
| **Namespace** | The stable, non-secret id a provider reports for where its sandboxes live: a Docker daemon, a Daytona organization, a machine. |
| **SandboxRef** | `{provider, namespace, id}`. The only identity. Serializable. `attach` resolves it by namespace. |
| **Durability** | What a provider promises about a sandbox outliving things: `process`, `machine`, or `remote`. |
| **Descriptor** | What a provider reports about itself: capabilities as data. Clients branch on it, never on a kind name. |

Kind names (`docker`, `daytona`, `lima`) appear in provider entries and nowhere else.

## Client API

`Sandboxes` is the entry point. It reads like a collection: attach one, build one, find many.

```rust
pub struct Sandboxes { /* private */ }

impl Sandboxes {
    /// Checks local structure only. Discovery, secrets and activation are lazy per entry.
    pub fn try_new(
        providers: impl IntoIterator<Item = (ProviderName, ProviderEntry)>,
        environments: Arc<dyn EnvironmentSource>,
        registry: &Registry,
        secrets: Arc<dyn SecretResolver>,
        options: CatalogOptions,
    ) -> Result<Self, Error>;
    /// Both levels from one file (the CLI, a bare Petri run).
    pub async fn from_config_file(
        path: &Path, registry: &Registry, secrets: Arc<dyn SecretResolver>,
        options: CatalogOptions,
    ) -> Result<Self, Error>;

    // Sandboxes
    pub async fn builder(&self, environment: &str) -> Result<SandboxBuilder, Error>;   // NoEnvironment if unknown
    pub async fn attach(&self, r: &SandboxRef) -> Result<Box<dyn Sandbox>, Error>;
    pub async fn find(&self, filter: LabelFilter) -> Result<Found, Error>;       // across every provider
    pub async fn destroy(&self, r: &SandboxRef) -> Result<(), Error>;

    // The catalog
    pub fn providers(&self) -> Vec<ProviderName>;
    pub fn provider(&self, name: &str) -> Result<ProviderHandle, Error>;
    pub async fn environments(&self) -> Result<Vec<EnvironmentName>, Error>;
    pub async fn environment(&self, name: &str) -> Result<Environment, Error>;
    pub async fn diagnostics(&self) -> Result<Vec<CatalogDiagnostic>, Error>;

    pub async fn shutdown(self) -> Result<(), Error>;
}

impl SandboxBuilder {
    pub fn image(self, r: &str) -> Self;             // and dockerfile, env, working_directory, user,
    pub fn label(self, k: &str, v: &str) -> Self;    // network, timers, cpu, disk, provider_config
    pub fn memory(self, v: &str) -> Self;
    pub fn spec(self, spec: SandboxSpec) -> Self;    // for callers that already hold a spec as data
    pub async fn create(self) -> Result<Box<dyn Sandbox>, Error>;
}

impl ProviderHandle {
    pub async fn describe(&self) -> Result<Descriptor, Error>;
    pub async fn validate_spec(&self, spec: &SandboxSpec) -> Result<(), Error>;
    pub async fn health(&self) -> Result<Health, Error>;
}

/// What `find` returns: every match it could reach, and the providers it could not.
pub struct Found {
    pub sandboxes: Vec<SandboxSummary>,              // reference, name, state, labels
    pub unavailable: Vec<ProviderName>,              // every entry whose query failed
    pub failures: Vec<ProviderFailure>,              // entry plus structured error
}

#[async_trait]
pub trait Sandbox: Send + Sync {
    fn reference(&self) -> SandboxRef;
    fn working_directory(&self) -> &Path;
    fn env(&self) -> &BTreeMap<String, String>;      // the sandbox's ambient variables
    async fn status(&self) -> Result<Status, Error>;
    async fn start(&self) -> Result<(), Error>;      // also brings a paused sandbox back
    async fn stop(&self) -> Result<(), Error>;
    async fn exec(&self, spec: ExecSpec, controls: ExecControls) -> Result<ExecOutcome, Error>;
    fn files(&self) -> &dyn Files;                   // get, put, list
    fn ports(&self) -> &dyn Ports;                   // expose, release
    fn endpoints(&self) -> Option<&dyn Endpoints> { None }   // optional capability: ssh, shell command, vnc
    fn containers(&self) -> Option<&dyn Containers> { None } // optional capability: one-shot containers
}
```

`Sandboxes` is a concrete type built once per process. Provider entries are given at construction. Environments are read from their source each time one is used, so a catalog that changes while the process runs, like Fabro's environment store, needs no rebuild. `Sandbox` is a trait because the value behind it is a built-in provider, a plugin child, or the fake, and the caller must not care which.

```rust
#[async_trait]
pub trait EnvironmentSource: Send + Sync {
    async fn names(&self) -> Result<Vec<EnvironmentName>, Error>;
    /// `Ok(None)` means the store has no environment with this name.
    async fn get(&self, name: &str) -> Result<Option<Environment>, Error>;
}
```

The library provides `StaticEnvironments`, a fixed list; `from_config_file` loads a file into one. A client whose environments are editable at runtime implements the trait over its own store. The trait is async and fallible because Fabro's store is a database: a storage failure is `Unavailable`, and only `Ok(None)` means the environment does not exist, so a flaky store is never read as a missing environment. `Environment::validate(&Descriptor)` is public so such a client can reject a bad edit when it is saved rather than when it is used.

`builder`, `environment` and `environments` are async because their source may be a database. A builder freezes the selected environment and provider binding. Field setters override individual template values; map setters merge keys, while `spec` replaces the whole template. An invalid size string stays an admission error, even if a later setter supplies another value.

`find` fans out to every provider entry and merges the results. A provider that does not answer is listed in `unavailable`, with its structured reason in `failures`, rather than failing the whole query, so a sweep can act on what it found and come back for the rest. Neither list implies absence or authorizes a replay. Inventory runs eight entries at a time with thirty seconds per entry by default, configurable through `CatalogOptions`. Results and failures are ordered deterministically by entry and identity. Equal duplicate refs collapse; conflicting duplicates or foreign refs invalidate that entry's batch. Different entry aliases remain different refs.

Rules every method obeys:

1. **Wire-expressible.** Data in, data or an opaque `Sandbox` out. No process handles, file descriptors, closures, or client-local paths. This is what lets protocol 3 carry a call to a child process and lets the fake serve the same API in memory.
2. **Identity is the ref.** Nothing else identifies a sandbox. Clients store refs and derive nothing. `attach` resolves only the saved provider-entry binding and checks its namespace before dispatch, so renaming or deleting the environment a sandbox was created from does not orphan the sandbox.
3. **Capabilities are data.** To know whether a sandbox can do something, read the descriptor or check an extension accessor for `Some`. Kind names are never a basis for behavior.

### Exec

`ExecSpec` is argv (no shell), env, working directory, timeout, and `tty`. `ExecControls` is a streamed stdin, an output sink, two cancellation levels (`term` then `kill`) and a terminal resize receiver. `ExecOutcome` reports `termination` (`exited`, `timed_out`, `terminated`, `killed`, `lost`), `exit_code`, `signal`, and output-loss counts. No built-in provider supports `tty` yet; each refuses it with `Unsupported`. Dropping the future requests cancellation; it does not confirm that the command has stopped. The provider owns bounded cleanup after the drop. `lost` means the execution outcome is unknown, not that the command or sandbox is known to be gone. Only a confirmed termination outcome or a successful sandbox `stop` establishes that the affected execution has ended.

### Files and ports

`Files` is `get(path, range)`, `put(path, bytes)` creating parents, and `list(path, depth)`. Paths address the workload; a relative path resolves against its working directory. Bytes move as owned streams, so a plugin transport keeps them off its control connection.

`Ports` is `expose(port, Expose { signed, ttl_ms }) -> Exposure { url, headers, expires_at_ms }` and `release(port)`. Some providers hold a real local forward until `release`.

### Errors

A closed set with stable snake-case codes, the same in Rust and on the wire:

`NoProvider`, `NoEnvironment`, `InvalidConfig { entry, path, message }`, `MissingSecret { entry, name }`, `NotFound`, `AlreadyExists { name, id }`, `NotOwned`, `NamespaceMismatch`, `Unavailable` (currently unreachable; does not establish that execution stopped or a resource was deleted), `Unauthenticated` (the backend rejected the configured credentials), `PermissionDenied` (valid credentials that do not permit this operation), `ResourceExhausted { retry_after_ms }` (a quota or rate limit refused admission), `Busy` (a prior instance is still going away or another mutating owner holds the fence), `Unsupported { capability }`, `Unhealthy { message }`, `Stale` (the plugin restarted; re-attach by ref), `InvalidSpec { path, message }`, `IncompleteCleanup { remaining }` (destroy or a failed create could not confirm cleanup; an empty list means the ids are unknown, not that nothing remains), `FenceLeaked`, `Transport`.

The three refusals are distinct from `Unavailable` so a client can tell bad credentials from a backend that is down, and none of them is a retry hint. `Unavailable`, `Stale` and `Transport` carry an `outcome` of `not_started` or `unknown`; it defaults to `unknown`, and `not_started` requires proof that nothing was admitted. A future unknown error code is a decoding failure with an unknown outcome, never `NotFound` or success.

## Configuration

`try_new` takes both levels of the catalog from wherever the client keeps them. Provider entries are operator-owned and rarely change. Environments come from any `EnvironmentSource`: a fixed list or a live store whose edits are visible on the next use. A client with neither calls `from_config_file` with an explicit path, so tools on one machine can share a catalog. Names at both levels are chosen by the operator; the library ships none.

```toml
[providers.docker]
plugin = "docker"                 # built in
config = { host = "unix:///var/run/docker.sock" }

[providers.daytona]
plugin  = "daytona"               # built in
config  = { api_url = "https://app.daytona.io/api", organization = "org_…" }
secrets = ["DAYTONA_API_KEY"]     # resolved through the application's SecretResolver, never stored here

[providers.local]
plugin = "host"                   # built in, durability: process

[providers.lima]
plugin = "lima"                   # a plugin: an absolute path and a checksum pin
path   = "/opt/sandbox-driver/plugins/sandbox-driver-lima"
sha256 = "9f2c…"                  # or dev = true during development

[environments.ci-linux]
provider = "docker"

[environments.ci-linux.spec]
source  = { image = "ghcr.io/lithoscomputer/ubuntu-24.04:slim-f8bbbfd81934" }   # Petri's pinned runner image
network = { mode = "block" }

[environments.cloud]
provider = "daytona"

[environments.cloud.spec]
source    = { dockerfile = "FROM buildpack-deps:noble\n" }
resources = { cpu = 2, memory = "4GB" }
timers    = { auto_stop = "60m" }

[environments.scratch]
provider = "local"

[environments.lima-dev]
provider = "lima"

[environments.lima-dev.spec]
source = { image = "ubuntu-lts" }
```

Per provider entry: `plugin` (the provider kind), `config` (whatever that provider's `config_schema` accepts, validated when the entry is first activated so a typo fails with the field named; the library never reads its contents), `secrets`, and for a plugin `path`, `sha256` or `dev`, `args`, `env`, `inherit_env`. A plugin entry must name an absolute `path` and either a `sha256` pin or `dev = true`; there is no search of `PATH` or of a plugin directory. A `sha256` pin together with `dev = true` is a decoding error, so a pin is never silently skipped. The two trust keys are flat because operators write them by hand; in Rust they decode to `PluginTrust`. The kinds `host`, `docker` and `daytona` are reserved for the built-in providers: an entry naming one of them with `path`, `sha256` or `dev` is `InvalidConfig`, and a reserved kind is never routed to the plugin loader, even when the application did not register that built-in. A third-party plugin picks another kind, such as `acme-daytona`.

Credentials and conveniences take different paths:

- **`secrets`** names the credentials the entry needs. The library resolves each name at entry activation through the explicitly supplied `SecretResolver` (Fabro uses its vault), and an unresolvable name is a `MissingSecret` error naming the entry. Values reach a built-in as `SecretValues` in its activation and a plugin child as explicit environment variables. A provider that accepts one of several credential forms says so in its `config_schema`; the library never guesses. Service `credential` names in a spec use the same resolver, at workload admission.
- **`inherit_env`** carries conveniences only. Every plugin child starts from an empty environment. An omitted list selects `PATH`, `HOME`, `TMPDIR` and `USER`; an explicit list replaces those defaults, and `inherit_env = []` yields exactly explicit `env` and resolved secrets. Values are copied from the supplied snapshot and frozen for the life of the entry. An unset convenience name is simply not set. A value in `env` wins over an inherited one; an `env` name that collides with a secret is a configuration error.
- Built-ins take their configuration only from the entry's `config` and resolved secrets, never from the ambient environment, which is what makes one process safe to run entries for different owners. Host's commands do inherit the calling process's environment, with secrets filtered out.

Secret values never appear in descriptors, saved specs, or errors. Provider config, explicit environment and arguments may contain sensitive values, so their `Debug` output is redacted.

Per environment: `provider` (an entry name) and `spec`, a `SandboxSpec` template the sandbox builder starts from: `source`, `resources`, `network`, `timers`, `labels`, `env`, `working_directory`, `workspace_ownership`, `user`, `services` and `container` (a typed workload description, below), and `provider_config` for the few per-sandbox settings that have no provider-neutral meaning, validated against the provider's `spec_schema` when it declares one. `Environment` and `ProviderEntry` derive `Deserialize`, so a client's own settings types can embed them directly.

Sizes are written with a unit and read the way Docker and systemd read them: `4GB`, `4G`, `4GiB` and `4Gi` all mean 4096 MiB, and `cpu` is whole cores. The library parses once; providers receive integers and never see the string. A provider that allocates in coarser units rounds up and reports what it gave you in `status`.

That single parse happens when a `SandboxSpec` is decoded. `resources` accepts `cpu`, `memory` and `disk` with units, and `timers` accepts `auto_stop`, `auto_archive`, `auto_delete` and `ttl` as durations (`60m`, `1h 30m`, `500ms`; `0s` explicitly disables a timer). The value is stored and always serialized in the integer form, `cpu_cores`, `memory_mb`, `disk_mb` and `*_ms`, which is also accepted on input. The grammar is exported as `parse_size_mib` and `parse_duration_ms` for the builder's `memory("8GB")` and for UIs that validate before saving.

Request types reject unknown fields rather than dropping instructions. That includes fields the selected mode does not take: an `allow` list on a network mode that is not an allow list is a decoding error. Descriptors may gain object fields, but an unknown enum capability fails decoding rather than being read as supported. An unknown status state becomes `unknown`, never a terminal state.

The `ci-linux` environment uses the image Petri runs process scopes in on Docker. Petri publishes these runners as `ghcr.io/lithoscomputer/ubuntu-<version>:<flavor>-<pin>`. Clients select the workload source; choosing an outer runner or a Docker-in-Docker helper image is provider implementation detail. If Daytona needs an outer runner to host that workload, the Daytona provider provisions it and routes operations to the workload, with no different recipe in Fabro or Petri.

## Identity and admission

`SandboxRef { provider, namespace, id }` is the durable identity value. `provider` is the operator's **provider-entry name**, not its kind and not an environment. `namespace` is a non-secret, backend-issued resource-domain identifier. The same configured backend reports the same namespace across reconnects; a different backend must report a different namespace even if sandbox ids happen to match. Identifiers are non-empty, at most 256 bytes, and contain no whitespace or control characters. Namespace values are opaque: clients must not synthesize them from URLs, credentials, the current environment, or provider-kind guesses.

`attach` and `destroy` resolve the saved provider binding and compare the provider's namespace with `SandboxRef::check_namespace` **before sending a sandbox operation**. A mismatch is `NamespaceMismatch`. A missing binding is `NoProvider`; failed contact is `Unavailable`. Neither is evidence of deletion. The library never scans for another kind or entry and silently redirects a ref. An operator may move a provider-entry name to a new entry after verifying the same namespace and access rights; renaming an entry otherwise needs an alias or rewriting the saved records. Deleting or editing an environment needs neither: refs and inventory do not depend on environments.

A ref is routing data, not authorization or proof of ownership. Applications' own ownership checks and lease records remain necessary; namespace agreement does not bypass them.

Admission saves the resolved spec and provider binding; a later start or recovery never rereads an edited environment. Applications persist their own admission and lease records. The provider persists whatever state its declared durability needs.

### Lazy startup

A cold catalog does not start every plugin or require every executable, backend and credential to be available. `try_new` checks local structure only. An environment that names a missing entry, or an entry with invalid structure, is recorded as a diagnostic (`Sandboxes::diagnostics`) and rejected when selected; unrelated entries stay usable.

On an entry's first use, the catalog:

1. **Discovers its schemas.** A built-in factory returns them directly. For a plugin, the loader verifies the executable against its `sha256` pin (or explicit `dev = true`) and runs it once with `--describe-schema`, a bounded, short-lived process given only the minimal platform environment and no config, secrets or backend access. See [plugin metadata discovery](#plugin-metadata-discovery).
2. **Validates and freezes the entry.** Config is checked against `config_schema`, required secrets are resolved, and the launch inputs are frozen. One provider is activated per entry per catalog. Editing an environment touches no backend; changing connection or launch settings needs a new catalog.
3. **Activates the provider.** A built-in factory builds it in process. The plugin loader starts the child, sends the config in `initialize`, and passes secret values in its environment. The provider's descriptor must match the discovered kind, version and schemas; disagreement fails before any sandbox operation.
4. **Checks each spec before mutation.** `SandboxSpec::validate_for` checks portable invariants and the descriptor's capabilities, and the catalog validates `provider_config` against `spec_schema`. A schema must declare draft-07, 2019-09 or 2020-12 and is compiled without fetching external references. Config and spec options are checked separately, and error messages omit instance values. No schema means the provider validates opaque options itself; it never means ignoring them.

## Providers

Host, Docker and Daytona are built in: the application registers each one with `Registry::builtin`, and their kinds are reserved, so none of them is ever loaded as a plugin. `Registry::plugins` registers the plugin loader for every other kind.

|  | host | docker | daytona |
| --- | --- | --- | --- |
| Factory | `sandbox_driver_host::HostFactory` | `sandbox_driver_docker::DockerFactory` | `sandbox_driver_daytona::DaytonaFactory` |
| Namespace | `host:<machine-id>` | `docker:<engine-id>` | `daytona:<org>` |
| Durability | `process` | `machine` | `remote` |
| Access | `owner_process` | `shared` | `shared` |
| Isolation | `none` | `container` | `container` |
| Sources | host directory | image | image, dockerfile, snapshot |
| Mounts host paths | yes | local daemon only | no |
| Network policy | provider default only | allow all, block | allow all, block, CIDR list, domain list |
| Resources | none | cpu, memory | cpu, memory, disk |
| Timers | none | none | auto stop, auto archive, auto delete, ttl |
| Optional capabilities | none | endpoints (shell command), services, containers | services, containers |

Each of these facts comes from the provider's descriptor at runtime; the table summarizes them. A request the descriptor does not list is refused with `Unsupported` before anything is admitted.

**Host** runs commands as child processes in a directory, on the machine of the process that activated it. One live Host instance owns its sandboxes, their process groups and their lifecycle; see [Host ownership and workspaces](#host-ownership-and-workspaces). Use `docker` for local sandboxes that must outlive the caller.

**Docker** takes one `config` key, `host` (`unix://`, `tcp://` or `http://`; default `unix:///var/run/docker.sock`). Services become sidecars on the workload's network, reached by service name. `provider_config` takes `auto_pull`, `platform`, `binds` and `host_network`; `binds` is refused unless the daemon is local. The stop fence is a daemon-scoped claim shared by every provider instance using that daemon; [Docker lifecycle coordination](docker-lifecycle.md) describes it.

**Daytona** takes `api_url`, `organization`, `target` (the Daytona region) and `runner_image` in `config`, and names `DAYTONA_API_KEY`, or `DAYTONA_JWT_TOKEN` together with `organization`, under `secrets`. Without services or `container` options, the workload is the Daytona sandbox itself, built from an image or Dockerfile into a snapshot named by its inputs and reused, or created from a Daytona snapshot. With services or `container` options, the provider creates a runner sandbox from a Docker-capable image and runs the workload as a container on the runner's network, beside its services, which it reaches at `127.0.0.1:<port>`. One-shot containers run on Docker inside the workload, so a direct workload needs an image that provides `docker`, `start-docker` and `python3`; without them `run` returns `Unsupported` before admitting anything. Daytona's control plane holds each sandbox's lifecycle state, so every provider instance shares one fence.

## Workloads

`create` receives the environment's template merged with the caller's overrides, after the library has validated it and converted every size and duration. Every field except `source` is optional; a field a provider does not support is refused with `Unsupported` naming it, never silently ignored.

```json
{
  "name": "petri-01jabc-l3",
  "source": {"image": "ghcr.io/lithoscomputer/ubuntu-24.04:slim-f8bbbfd81934"},
  "resources": {"cpu_cores": 2, "memory_mb": 4096, "disk_mb": 20480, "gpus": 0},
  "network": {"mode": "cidr_allow_list", "allow": ["10.0.0.0/8"]},
  "timers": {"auto_stop_ms": 3600000},
  "labels": {"fabro.run": "01JABC…", "petri.workspace": "01JABC…/build"},
  "env": {"CI": "1"},
  "working_directory": "/workspace",
  "user": "root",
  "services": {
    "postgres": {"image": "postgres:16", "env": {"POSTGRES_PASSWORD": "x"}, "ports": [5432],
                 "ready": {"command": ["pg_isready"], "interval_ms": 2000, "timeout_ms": 1000,
                           "retries": 30, "deadline_ms": 60000}}
  },
  "container": {"init": true, "capabilities_add": ["SYS_PTRACE"]},
  "provider_config": {}
}
```

- `source` is exactly one of `{"image": …}`, `{"dockerfile": …}` (the file's text), `{"snapshot": …}` (a provider-known id) or the bare string `"host_directory"`. The descriptor's `sources` lists which a provider accepts. A host directory has no image: the directory is `working_directory`, and `workspace_ownership` says whether it is `designated` (caller-owned, never removed by destroy; the default when a path is given) or `managed` (provider-owned, removed on confirmed destroy; a temporary directory when no path is given). Ownership is only valid with a host directory source.
- `resources` are whole cores and MiB. A provider rounds up if its backend allocates in coarser units and reports the result in `status`. A non-zero `gpus` it cannot provide is `Unsupported`, never dropped.
- `network.mode` is `provider_default`, `allow_all`, `block`, `cidr_allow_list` or `domain_allow_list`; the descriptor's `network` lists which a provider honours. A mode it does not list is `Unsupported`, except `provider_default`, which every provider honours whether listed or not, so a spec without `network` is accepted everywhere. The two allow-list modes carry their entries under one `allow` key.
- `timers` are milliseconds. The descriptor's `capabilities.timers` lists each enforced timer; a request for an unlisted one is `Unsupported`.
- `labels` and `env` are string maps. Labels round-trip exactly; env reaches every process in the sandbox. Env keys must be non-empty and contain no `=` or NUL, and values contain no NUL, because either would change the variable the workload receives.
- `working_directory` and `user` are where commands run and as whom; the working directory actually used is returned on the sandbox handle.
- `services` are named containers beside the workload, keyed by lowercase DNS label: an image, env, TCP ports, an optional registry credential name, and an optional readiness check. See below.
- `container` is the typed subset of container options a job can ask for: `init`, `privileged`, `capabilities_add`, `capabilities_drop`, `dns`, `extra_hosts`, `shm_size_mb`. `None` is unspecified, while `Some(false)` is an explicit request. The descriptor's `capabilities.container_fields` lists exactly which a provider honours, independently of service support; the rest are `Unsupported`, including unsupported explicit false values.
- `provider_config` belongs to the provider, for the few settings with no provider-neutral meaning. A provider describes it with a `spec_schema` and the library validates overrides against it; otherwise the provider validates it.

`source` describes the workload the caller wants to execute, not a provider's VM runner or nested-Docker helper. Sandbox `exec`, `working_directory`, ambient `env`, and file operations address that workload and its workspace. There is no caller-selectable outer-runner execution target. A one-shot container uses its own requested image but shares the workload's workspace, network and service reachability. Any outer runner, nested Docker setup, helper image, snapshot cache or backend-specific job recipe is the provider's responsibility; Petri and Fabro supply the same portable workload spec regardless of provider.

### Services

A service's ports are reachable **from the workload** and its one-shot containers, not published on the host. `status.services` reports the host and port the workload uses, because on Docker that is a network alias and on a Daytona runner it is localhost. Addresses may change across a restart, and an unavailable status does not present stale addresses as current.

A readiness check is argv run inside its service, without an implicit shell; exit zero passes. It states its whole budget: `interval_ms`, a per-attempt `timeout_ms`, `retries` and an overall `deadline_ms`, all required and non-zero. The deadline bounds the wait even when the attempts would take longer. A timeout longer than the deadline, or an interval that leaves no room for a second attempt, is `InvalidSpec`, because the check could never use its budget. Without a check the provider only confirms the service started; it makes no claim about application readiness.

### Status

`Status` carries the reference, state, name, labels, the image and snapshot in use, the resources actually allocated after rounding, the effective network policy, the service addresses, and `web_url`, a console URL when the provider has one. An absent field was not reported, not zero. States include `unavailable` (unreachable, not known gone) and `lost` (established gone without a confirmed destroy, never inferred from failed contact), and the backend's own `paused` and `archived`.

### What crosses a provider

- **The name is a hint.** `spec.name` is what the caller would like the sandbox called. A provider uses it as is, adapts it to its backend's rules, or generates its own, and reports the name it used. If the backend enforces unique names and the hint collides, it may return `AlreadyExists` with the existing id; it is not required to detect duplicates. Callers find sandboxes again by labels and by ref, never by name.
- **Labels round-trip exactly.** Whatever keys and values the caller sets come back unchanged from `status` and match in `list` filters. A backend that cannot store a value as given encodes it reversibly; one that cannot store it at all refuses with `InvalidSpec` naming the label. A provider never truncates or drops one.
- **Unavailable is not lost.** When a provider cannot reach a sandbox but does not know it to be gone, it reports state `unavailable` and fails commands with `Unavailable`. The library does not infer deletion or replace the sandbox because contact was lost. The caller decides how its application responds to the uncertainty.

## Lifecycle, fences and uncertain outcomes

There is no pause, resume, archive or recover. When the backend paused or archived a sandbox, on its own timer or through another tool, `start` brings it back to running; status reports `paused` or `archived` until then. Docker unpauses the container, so its processes carry on.

- **Create and start.** Both succeed only once the workload accepts execution and every declared readiness check has passed. Start uses the admitted spec, restores services from it, and checks readiness again. A failed create attempts bounded cleanup of everything it provisioned.
- **Stop.** `stop` and `start` are a fence around the whole sandbox workload. Before draining, `stop` blocks new exec, service and one-shot admissions. It succeeds only after every previously admitted command, service and one-shot container has ended and the workspace is intact. This includes execution admitted through another handle or provider instance. Providers coordinate one fence across instances (`access: shared`), or enforce one mutating owner (`access: owner_process`) and reject conflicting mutations with `Busy`. `start` fails with `Busy` while a previous stop is still draining; after stop then start, no execution from before the stop remains.
- **A stop acknowledgement is not a fence.** Unconfirmed termination is `FenceLeaked`; failed contact is `Unavailable` or `Transport` with an unknown outcome. No timeout, lost connection or plugin exit is ever reported as a successful stop.
- **Destroy.** `destroy` stops execution and confirms removal of everything the provider manages for the sandbox: services, one-shot containers, networks and helpers. An already-absent sandbox is success only once no associated managed resources remain. If cleanup cannot be confirmed, the error is `IncompleteCleanup` with any known remaining resource kinds and ids; an empty list means the ids are unknown, not that nothing remains. The provider keeps labels or other discovery data on what remains, including partially created resources, so the caller can reconcile them.
- **Absence.** `NotFound` requires authoritative absence in the checked namespace. `Unavailable`, status `unknown` and exec termination `lost` do not mean gone. A failed readiness check may follow partial creation. No error code alone is an instruction to retry safely.
- **Restarts and replays.** Connection loss, a plugin crash, or `Stale` does not establish whether an in-flight mutation took effect or whether its command stopped. Restarting a plugin restores the transport only; reattaching a sandbox restores access only. The library never automatically replays a mutation whose outcome is uncertain, and never restarts a sandbox workload. Fabro or Petri decides whether to wait, inspect, stop, retry, replace, or fail its work using these primitives.

## Host ownership and workspaces

Host is `durability: process` and `access: owner_process`, with a namespace stable for the machine. Sandbox ids are bound to the provider instance that created them, so a restart cannot reuse another sandbox's identity. One live instance owns admissions, process groups and lifecycle state. A second instance, in this process or another, is not an observer or a shared registry and cannot gain access from a path or a ref: if the owner is alive it gets `Busy`, and if the owner is gone it gets `Unavailable`, never `NotFound`. Reattaching after the owner dies is not promised.

Each Host instance keeps its process-group fence state in a temporary directory it owns. `shutdown()` fences and destroys its sandboxes with bounded cleanup; process loss alone is not proof that children died. Separate server and worker processes cannot both attach to the same Host workload; an application that needs live access from another process routes operations to the owner. A run record can show history but is not a live sandbox handle.

A designated workspace stays caller-owned and is never removed by destroy. A managed workspace is provider-owned and removed on confirmed destroy. Files left after a worker exits are not a running or attachable sandbox, and their existence proves neither that execution ended nor who owns them. An application may create a new sandbox over a retained designated workspace once it has settled that the prior owner is gone, or choose a durable provider for restartable execution. That is application recovery policy, never an automatic Host restart or adoption. A missing or unconfigured Host entry affects only work that selects it.

## The provider interface

A provider, built in or plugin, implements two traits from the crate root.

- `ProviderFactory::discover(&PluginLocation)` receives only the entry name (for errors), kind, path and trust, and returns `ProviderSchemas`. Built-in factories return their metadata directly; the plugin loader verifies and probes the executable.
- `ProviderFactory::activate(Activation)` receives the selected entry name, frozen connection and launch configuration, discovered schemas, resolved launch environment and separate redacted `SecretValues`, and returns an `Arc<dyn Provider>`.
- `Provider` supplies `describe`, `health`, `create(WorkloadAdmission)`, `attach(&SandboxId)`, `list(&LabelFilter)`, `destroy(&SandboxId)` and `shutdown`. The catalog checks the namespace before routing `attach` and `destroy`. A provider also keeps a reconnect from moving an admitted call to another namespace, and invalidates old sandbox handles when its generation changes. `WorkloadAdmission` separates credential values from the persistable spec; a provider keeps the admission for restart.
- `Sandbox` supplies the reference, workload environment and workspace, `status`, `start`, `stop`, `exec`, `files` and `ports`. Optional `endpoints` and `containers` return `None` unless supported. All errors are `sandbox_driver::Error`.
- `ExecControls` carries one owned stdin reader, an awaited output sink, `term` and `kill` tokens and a latest-value terminal resize receiver.
- `OneShotSpec` takes its own `OneShotImage`, never the workload `Source`: a registry `image`, or a `build` from a context directory in the workload workspace, resolved against the sandbox working directory, with an optional Dockerfile path, a tag that keys the build cache, and a `reuse` flag. Its command is an optional `entrypoint` plus `args`, not exec argv, so arguments alone reach the image's own entrypoint, as a GitHub Docker action expects. A one-shot's execution participates in the stop fence, and its resources are removed when it finishes or the sandbox is destroyed.

`SandboxSpec::validate_for` and `Environment::validate` check portable invariants and descriptor capabilities. They do not replace JSON Schema or backend validation.

### The descriptor

```json
{
  "schemas": {
    "kind": "lima", "version": "0.3.0",
    "config_schema": {"$schema": "https://json-schema.org/draft/2020-12/schema", "type": "object", "properties": {"vm_type": {"type": "string"}}},
    "spec_schema": null,
    "secrets": []
  },
  "namespace": {"id": "lima:7f3a…", "scope": "machine"},
  "isolation": "vm",
  "durability": "machine",
  "access": "owner_process",
  "sources": ["image"],
  "locality": {"host_address": "192.168.5.2", "mounts_host_paths": true},
  "resources": ["cpu", "memory"],
  "network": ["allow_all"],
  "ports": {"exposable": "any"},
  "capabilities": {"endpoints": [], "services": false, "containers": false,
                   "container_fields": [], "timers": ["auto_stop"]}
}
```

`schemas` is the credential-free part: `kind`, `version`, `config_schema` (a JSON Schema for the entry's `config`; use `oneOf` when you accept alternative forms), an optional `spec_schema` for the spec's `provider_config`, and `secrets`, the credential names the provider expects, so a catalog can check an entry names them all. None of it may need a backend.

`namespace.id` must be stable across restarts and must differ when the sandboxes would. The library refuses a descriptor without one. `isolation` is the workload's security boundary: `none`, `container` or `vm`. `access` is `owner_process` when only the live instance that created a sandbox can operate it, or `shared` when instances reaching the same namespace coordinate one stop fence. `capabilities.container_fields` lists exactly which `container` options the provider honours and `capabilities.timers` which timers it enforces, so a client knows in advance what will be refused. Every advertised list is a set; order and repetition carry no meaning.

`durability` is a promise about restarts. A provider that declares `machine` or `remote` must make `attach` and `list` work after it is stopped and started again with the same entry, from whatever it chose to persist. Where it keeps that state is its own choice; a `state_dir` key in its `config_schema` keeps two entries from sharing one. `process` promises nothing across a restart.

### Optional capabilities

Three groups of calls and fields that only some providers can offer. They are defined here, not by providers: a provider declares which it implements in `capabilities`, and a client checks before relying on one. A provider cannot add a fourth; a new group is added only when a second client and a second provider both need it. Pause, resume, archive and recover were left out because no client calls them; they can return as a group when one does.

- `endpoints`: a set from `ssh` (`ssh(ttl_ms)`, `ssh_revoke(token)`), `shell_command`, `vnc`, reached through `Sandbox::endpoints`.
- `services`: `true` if `create` accepts the spec's `services`.
- `containers`: `true` if `Sandbox::containers` runs one-shot containers (`OneShotSpec`), streamed like exec.

Docker offers all three, with `shell_command` as its only endpoint. Daytona offers services and containers. Host offers none: it runs commands as processes in a directory and has nothing to put a service in. Protocol 3 does not carry endpoints or one-shot containers yet, so a plugin cannot offer them; the loader masks them out of a plugin's descriptor.

## Plugins

A plugin is an executable that serves one provider over protocol version 3. The library starts it, writes JSON-RPC requests to its stdin and reads responses from its stdout; stderr is captured as plugin logs. [The plugin protocol](protocol.md#16-protocol-version-3-the-shared-contract-over-a-process-boundary) specifies the wire: framing, the data channels that carry exec and file bytes outside the control pipe, transport budgets, and the method list. The rest of that document describes protocol version 2, which is being removed.

### Using a plugin

Add a provider entry that names the plugin's kind, the absolute path of its executable, and a checksum pin (or `dev = true` while developing it), then give it an environment:

```toml
[providers.lima]
plugin = "lima"
path   = "/opt/sandbox-driver/plugins/sandbox-driver-lima"
sha256 = "9f2c…"
config = { vm_type = "vz" }

[environments.lima-dev]
provider = "lima"

[environments.lima-dev.spec]
source = { image = "ubuntu-lts" }
```

The application registers the loader once, with `Registry::new().plugins(Arc::new(PluginLoader::default()))` beside its built-ins. Nothing else in the calling program knows the environment is served by a child process:

```rust
let sandbox = sandboxes.builder("lima-dev").await?.create().await?;
```

On first use the catalog verifies the executable, checks the entry's `config` against the plugin's `config_schema` with the field named on failure, and resolves its `secrets`. If the plugin's own backend is down, `sandboxes.provider("lima")?.health().await` says so before any sandbox is attempted.

In Fabro the two levels live where they already do: the provider entry in server settings, the environment in the environments UI, where the form shows the plugin's config fields from its schema.

### Writing a plugin

`sandbox_driver_protocol::v3::Plugin::new(schemas, factory)` and `run_plugin` are the Rust SDK. A plugin implements `ProviderFactory` and `Provider` exactly as a built-in does; `run_plugin` answers `--describe-schema` before constructing anything else, then serves stdio. `sandbox-driver-fixture-plugins` is the worked example: it serves the Host and Docker built-ins under the non-reserved kinds `test-host` and `test-docker`. A plugin in another language implements the wire directly.

What the library promises a plugin, and expects of it:

- **The schema probe.** Run with `--describe-schema`, the plugin prints its `ProviderSchemas` as one JSON object on stdout and exits, without config, secrets or backend access.
- **Supervision.** The plugin loader starts one child per activated entry, on that entry's first use, with exactly the frozen environment described under [Configuration](#configuration) plus the resolved secret values, and the entry's `args`. Each start is a generation. Handles keep the generation that issued them and fail with `Stale` once it ends; the next call starts a new generation, which must report the same schemas and namespace. Only the transport is restored: the call in flight when a child died reports an unknown outcome or `lost`, and is never sent again.
- **The handshake.** `initialize` carries the protocol version, the data transport, the entry name, the entry's `config` (already validated) and the *names* of its secrets. Secret values never cross the control pipe; the plugin reads them from its environment. Do not depend on any other environment variable being set. `describe` must then return the discovered schemas.
- **Bounded work.** `shutdown` ends supervised children with bounded cleanup, and a child exits on stdin EOF. Neither proves that remote workload execution has stopped.

### Plugin metadata discovery

`sandbox_driver_protocol::metadata` implements the credential-free discovery step, and the [plugin protocol](protocol.md#15-shared-contract-metadata-probe) specifies the probe a plugin answers.

`SchemaDiscovery` starts nothing when constructed. A `discover` call takes only a `PluginLocation` (entry name, kind, path, trust), never the entry's config, arguments, environment or secrets. The path must be absolute; there is no search of the caller's `PATH`. Discovery checks the checksum, or explicit development trust, and only then runs the executable. Probe stderr is logged when the probe fails and never put in an error. A Rust plugin can call `metadata::write_schema` before constructing its provider or loading settings, then exit.

Default budgets are five seconds for the whole discovery call, 1 MiB of stdout, 64 KiB of stderr, four concurrent probes, and 64 cached binaries. A probe beyond the concurrency budget waits within its caller's timeout; concurrent discoveries of one binary share a single probe. Both pipes are drained concurrently and bounded. On Unix the probe runs in its own process group, which is killed when the probe returns, fails, times out or is cancelled, so descendants do not outlive it.

The cache holds metadata only, keyed by the actual SHA-256 of the executable. Every lookup rehashes the executable and checks that location's trust, even on a cache hit. Changed bytes require rediscovery; failed probes are not cached. `DiscoveredPlugin` keeps the canonical executable path, digest, schemas, and whether a pin was verified. The loader calls `verify_unchanged` immediately before starting the child, and the catalog compares the provider's descriptor with the discovered schemas before any sandbox operation. Cached metadata never supplies namespace or capability facts. The configured kind must match the discovered one.

A missing, relative, non-executable or mismatched executable is `InvalidConfig` naming the entry and the `path`, `sha256` or `plugin` field; a mismatch reports both digests. A probe that fails, times out or prints anything but one schemas object is `Unavailable` with outcome `not_started`.

Probing executes trusted code, not sandboxed code. The executable is hashed and then executed by path, so installation directories and executables must be protected against concurrent modification. The checksum covers the executable bytes, not interpreters, shared libraries, or dependencies.

## Conformance

`sandbox_driver_conformance::Conformance` runs against a catalog, an environment and a set of provider-specific commands (a probe with its expected output, and a long-running command). It creates one sandbox per check and cleans it up afterwards, and reports each executed check: identity and inventory (including a label with awkward values that must round-trip), binary file ranges and preservation, streamed exec, and the stop fence across two handles. With `with_peer` and a second, separately activated catalog for the same entry, it also checks the fence across provider instances.

The same suite runs against the fake in the routine tests, against Host in the routine tests, against Docker with `mise run test:docker`, against Daytona with `mise run test:live`, and against the fixture plugins over protocol 3. Passing it is not certification of everything above: workload targeting, services and one-shot containers, restart recovery for durable providers, failure injection and transport loss are checked by each provider crate's own integration tests.

## Testing

```rust
let sandboxes = sandbox_driver_testing::fake();
```

The fake lives in `sandbox-driver-testing`, which consumers add as a dev-dependency; the core library exports no fake. It implements the required in-memory lifecycle, identity, files and scripted streaming execution. Use `FakeProvider::script` to define command responses and `FakeProvider::sandboxes` to keep access to its call log. Unscripted commands fail; no command executes on the host. Clones share workload state and call history. It advertises no optional services, container, endpoint or port capabilities.

## CLI

`lithos-sandbox` is the command-line client of this API and uses the same catalog: provider entries and environments, read from one file. Host, Docker and Daytona are linked into it and run in its process; every other kind is a plugin, launched over protocol version 3 by the plugin loader. With no catalog file it has one entry and one environment of the same name for each built-in.

```
lithos-sandbox providers                     # provider entries from the catalog
lithos-sandbox provider describe daytona
lithos-sandbox provider health daytona
lithos-sandbox environments
lithos-sandbox create ci-linux --label job=1842
lithos-sandbox exec <ref> -- make test
lithos-sandbox cp <ref>:/workspace/out ./out
lithos-sandbox find --label job=1842         # across every provider
lithos-sandbox destroy <ref>
```

The [CLI guide](https://github.com/lithoscomputer/sandbox-driver/blob/main/docs/cli.md) describes every command, where the catalog file is found, and its defaults.

## Design rules

The rules the library holds itself and its clients to. Contributions are reviewed against them.

1. Clients never see a kind name except as data in a descriptor.
2. Every client-facing method is wire-expressible.
3. A provider reports its namespace, durability, and capabilities. The library trusts the descriptor and nothing else.
4. The required interface grows only when a second provider and a second client both need the call. Vendor-only operations are optional capabilities or stay out.
5. Built-ins get no special API. They implement the same traits a plugin does, and the conformance suite runs against them too.
6. The library owns config, discovery, trust, and supervision. Clients configure them.
7. Connection and trust settings live on provider entries; what to build lives on environments. Neither level repeats the other.
8. Bulk bytes never share a pipe with control messages. Streams get their own connections; stop and health are never queued behind data.

## Status

Protocol version 3. The crates are pre-1.0 and the public API may change before 1.0.

Prior art: Jupyter kernelspecs and `jupyter_client`, Kubernetes CRI and RuntimeClass, the OCI runtime spec, HashiCorp go-plugin, MCP servers.
