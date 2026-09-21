//! Host (local) sandbox provider.
//!
//! A supported library for in-process embedding, and the implementation
//! behind the same-named plugin executable. An application either links
//! this crate and constructs the provider directly, or launches the
//! executable and reaches it through `sandbox-driver-protocol`. Both
//! present the same trait family.
//!
//! The base case of the provider family: sandboxes are directories on the
//! local machine, commands run as the calling user, and there is **no
//! isolation boundary** — the provider declares `Isolation::None`.
//!
//! A workspace is either **designated** (a caller-owned directory named in
//! `SandboxSpec::working_directory`; `delete` never touches its contents) or
//! **managed** (created and removed by this provider). An explicit
//! `workspace_ownership: Managed` transfers ownership of a named directory;
//! without it, a named directory remains designated.
//!
//! The Host provider advertises normalized Search, Git, and
//! background-services facets. The host environment must therefore provide
//! the commands documented by [`sandbox_driver::Search`] and
//! [`sandbox_driver::Services`], plus `git`, on `PATH`.
//!
//! # Runtime behavior
//!
//! Async on Tokio; the caller owns the runtime. This crate spawns tasks
//! only for stream pumping inside a running `exec` call and the stderr
//! tail reader of a spawned stdio process; both end when their process
//! ends. On Linux and macOS, a sentinel pins each process group until stop.
//! `stop` fences all work before returning; `start` permits a new generation.
//! [`HostProvider::with_registry`] keeps private records in a caller-owned
//! directory. After a restart, attach and list read those records. A recovery
//! fence writes markers and observes process death without signalling saved
//! ids. Other platforms retain direct process execution and do not offer this
//! crash fence.
//!
//! A designated directory needs no record to come back: its sandbox id is
//! derived from the canonical path (`host-dir-<hex>`), so any provider
//! instance, in any process, attaches to it by id and adopts it into its own
//! registry. Creating a sandbox on the same directory twice yields the same
//! id.
//! Temporary providers end owned process groups when their last owner drops.
//! Caller-owned registries retain groups for explicit stop or recovery.
//!
//! A managed workspace is known only to the registry that created it. A
//! second process reaches it through [`HostProvider::observe_registry`]: a
//! read-only view of that registry whose handles carry the owner's record
//! (id, labels, ownership, state) and work in the workspace, while every
//! lifecycle change stays the owner's. [`HostProvider::attach_directory`]
//! finds a recorded sandbox by its workspace path.

mod access;
mod exec;
mod fence;
mod fs;
mod registry;

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Weak};
use std::time::{Duration, SystemTime};
use std::{env, io, iter};

use async_trait::async_trait;
use sandbox_driver::{
    Action, Capabilities, Error, EventContext, EventEmitter, EventSubject, Exec, ExecSpec,
    Filesystem, HealthStatus, Isolation, LifecycleTimers, PlatformInfo, PreviewUrls, Progress,
    ProgressCode, ProviderHealth, ProviderKind, ResourceKind, Resources, Result, Sandbox,
    SandboxFilter, SandboxId, SandboxProvider, SandboxSource, SandboxSpec, SandboxState,
    SandboxStatus, WorkspaceOwnership,
};
use tokio::fs as tokio_fs;
use tokio::sync::Mutex;

use crate::access::HostPreview;
pub use crate::exec::HostExec;
use crate::exec::effective_env;
use crate::fence::ProcessGroups;
pub use crate::fs::HostFs;
use crate::registry::Record;

type HandleRegistry = Mutex<HashMap<SandboxId, Arc<HostSandbox>>>;

/// The provider kind every Host error and event reports.
pub(crate) fn host_kind() -> ProviderKind {
    ProviderKind::try_new("host").expect("static kind is valid")
}

/// A directory-backed provider. Use [`Self::with_registry`] to preserve
/// sandbox identity across provider or plugin restarts, and
/// [`Self::observe_registry`] to reach another process's sandboxes.
pub struct HostProvider {
    kind:            ProviderKind,
    capabilities:    Capabilities,
    root:            PathBuf,
    /// A registry another process owns, read and never written; see
    /// [`Self::observe_registry`].
    observed:        Option<PathBuf>,
    cleanup_on_drop: bool,
    registry:        Arc<HandleRegistry>,
}

impl HostProvider {
    /// The id a designated directory attaches by, from any provider
    /// instance: canonicalizes `path` and derives the `host-dir-<hex>` id.
    /// `None` when the path does not resolve or the id would exceed the
    /// id length limit.
    pub async fn directory_id(path: &Path) -> Option<SandboxId> {
        let canonical = canonical_directory(path).await.ok()?;
        directory_id(&canonical)
    }

    pub fn new() -> Self {
        Self::at(
            env::temp_dir()
                .join("sandbox-driver-host")
                .join(registry::fresh_id()),
            true,
        )
    }

    /// Opens a caller-owned registry. Only one provider process may use this
    /// directory at a time. The caller retains it for recovery and prune.
    pub async fn with_registry(root: impl AsRef<Path>) -> Result<Self> {
        registry::private_directory(root.as_ref()).await?;
        let root = tokio_fs::canonicalize(root.as_ref())
            .await
            .map_err(|e| Error::io("resolving host registry", e))?;
        Ok(Self::at(root, false))
    }

    /// A temporary provider that also reads the registry another process
    /// owns at `root`, without writing to it: the owner stays its only
    /// writer. A sandbox recorded there attaches by id or by directory
    /// ([`Self::attach_directory`]) as a read-only handle: it describes
    /// the sandbox from the owner's current record, runs commands in the
    /// workspace, and reads and writes its files, while `start`, `stop`,
    /// and `delete` are refused with [`Error::ReadOnly`]. Its commands
    /// run in this provider's own process groups, which end when the
    /// handle drops; the owner's fence does not cover them, and the
    /// owner's lifecycle state does not gate them, so a stopped sandbox's
    /// retained workspace stays usable. `list` reports the observed
    /// sandboxes beside this provider's own. A missing `root` is an empty
    /// registry. Sandboxes this provider creates live in its own
    /// temporary registry, as with [`Self::new`].
    pub fn observe_registry(root: impl Into<PathBuf>) -> Self {
        let mut provider = Self::new();
        provider.observed = Some(root.into());
        provider
    }

    fn at(root: PathBuf, cleanup_on_drop: bool) -> Self {
        Self {
            kind: host_kind(),
            capabilities: host_capabilities(),
            root,
            observed: None,
            cleanup_on_drop,
            registry: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// The registries this provider reads: its own, then the observed one.
    fn registry_roots(&self) -> impl Iterator<Item = &Path> {
        iter::once(self.root.as_path()).chain(self.observed.as_deref())
    }

    async fn load(&self, id: &SandboxId) -> Result<Arc<HostSandbox>> {
        let mut registry = self.registry.lock().await;
        if let Some(sandbox) = registry.get(id) {
            let sandbox = sandbox.clone();
            // An owned handle leaves the cache when it is deleted; an
            // observed one learns of its owner's delete here.
            if sandbox.observed.is_some() && sandbox.status().await?.state == SandboxState::Deleted
            {
                registry.remove(id);
                return Err(registry::missing(id));
            }
            return Ok(sandbox);
        }
        let (record, observed) = self.read_record(id).await?;
        if record.state == SandboxState::Deleted {
            return Err(registry::missing(id));
        }
        self.cache_handle(
            &mut registry,
            record,
            observed,
            EventEmitter::new(self.kind.clone(), None),
        )
    }

    /// The record for `id` from this provider's own registry, or else
    /// from the observed one, returned with that registry's root so the
    /// handle knows it is read-only.
    async fn read_record(&self, id: &SandboxId) -> Result<(Record, Option<PathBuf>)> {
        match registry::read(&self.root, id).await {
            Ok(record) => return Ok((record, None)),
            Err(Error::NotFound { .. }) => {}
            Err(error) => return Err(error),
        }
        let Some(observed) = &self.observed else {
            return Err(registry::missing(id));
        };
        let record = registry::read(observed, id).await?;
        Ok((record, Some(observed.clone())))
    }

    /// The id of the live sandbox recorded for the canonical `workspace`,
    /// in this provider's own registry first, then the observed one.
    async fn recorded_at(&self, workspace: &Path) -> Result<Option<SandboxId>> {
        for root in self.registry_roots() {
            let found = registry::records(root).await?.into_iter().find(|record| {
                record.state != SandboxState::Deleted && record.workspace == workspace
            });
            if let Some(record) = found {
                return Ok(Some(record.id));
            }
        }
        Ok(None)
    }

    /// Builds the shared handle for `record` and caches it in `handles`,
    /// the locked handle registry. Every handle a provider hands out is
    /// built here, with its process groups under the provider's own root,
    /// so attached handles for one sandbox share one live state. A record
    /// read from an `observed` registry yields a read-only handle.
    fn cache_handle(
        &self,
        handles: &mut HashMap<SandboxId, Arc<HostSandbox>>,
        record: Record,
        observed: Option<PathBuf>,
        events: EventEmitter,
    ) -> Result<Arc<HostSandbox>> {
        let sandbox = Arc::new(HostSandbox::new(self, record, observed, events)?);
        handles.insert(sandbox.record.id.clone(), sandbox.clone());
        Ok(sandbox)
    }

    /// Attaches to the sandbox whose workspace is the directory at `path`,
    /// as this provider's registry or the observed one records it: a
    /// managed workspace comes back with its id, labels, ownership, and
    /// state, and one the observed registry records as a read-only
    /// handle. A directory no live record names is `NotFound`, with the
    /// path as the id; a designated directory without a record attaches by
    /// its path-derived id instead (see [`Self::directory_id`]).
    #[tracing::instrument(skip_all, fields(provider_kind = %self.kind, path = %path.display()), err)]
    pub async fn attach_directory(
        &self,
        path: &Path,
        events: Option<EventContext>,
    ) -> Result<Arc<dyn Sandbox>> {
        let emitter = EventEmitter::new(self.kind.clone(), events);
        let handle_emitter = emitter.clone();
        emitter
            .run(
                EventSubject::sandbox(None),
                Action::Attach,
                |_| async move {
                    let Ok(workspace) = canonical_directory(path).await else {
                        return Err(missing_directory(path));
                    };
                    let Some(id) = self.recorded_at(&workspace).await? else {
                        return Err(missing_directory(path));
                    };
                    let sandbox = self.load(&id).await?;
                    Ok(Arc::new(sandbox.with_emitter(handle_emitter)) as Arc<dyn Sandbox>)
                },
            )
            .await
    }

    /// A designated directory named by a path-derived id, with no record in
    /// this registry: another process created it, or none did. The
    /// directory must exist; the sandbox is recorded here from now on with
    /// the identity a fresh create would give it.
    async fn adopt_directory(&self, id: &SandboxId) -> Result<Arc<HostSandbox>> {
        let Some(path) = directory_from_id(id) else {
            return Err(registry::missing(id));
        };
        let Ok(workspace) = canonical_directory(&path).await else {
            return Err(registry::missing(id));
        };
        if directory_id(&workspace).as_ref() != Some(id) {
            // A symlink or a non-canonical spelling: the id names another
            // path than the one it resolves to.
            return Err(registry::missing(id));
        }
        registry::private_directory(&self.root).await?;
        let record = Record {
            version: 1,
            id: id.clone(),
            name: None,
            workspace,
            ownership: WorkspaceOwnership::Designated,
            env: BTreeMap::new(),
            labels: BTreeMap::new(),
            state: SandboxState::Running,
            created_at: SystemTime::now(),
        };
        registry::write(&self.root, &record).await?;
        let mut registry = self.registry.lock().await;
        self.cache_handle(
            &mut registry,
            record,
            None,
            EventEmitter::new(self.kind.clone(), None),
        )
    }
}

/// No live record names the directory at `path`.
fn missing_directory(path: &Path) -> Error {
    Error::NotFound {
        resource: ResourceKind::Sandbox,
        id:       path.display().to_string(),
    }
}

/// The canonical path of an existing directory.
async fn canonical_directory(path: &Path) -> Result<PathBuf> {
    let metadata = tokio_fs::metadata(path).await.map_err(|error| {
        Error::io(
            format!("designated directory {} is not usable", path.display()),
            error,
        )
    })?;
    if !metadata.is_dir() {
        return Err(Error::invalid_spec(
            "working_directory",
            "designated path is not a directory",
        ));
    }
    tokio_fs::canonicalize(path).await.map_err(|error| {
        Error::io(
            format!("resolving designated directory {}", path.display()),
            error,
        )
    })
}

/// Where a new sandbox's workspace comes from, decided once from the spec.
enum WorkspacePlan {
    /// A caller-owned directory that must already exist; `delete` never
    /// touches it.
    Designated(PathBuf),
    /// A caller-named directory this provider creates if needed and owns
    /// from then on.
    ManagedNamed(PathBuf),
    /// A directory under the sandbox's registry entry, created here and
    /// owned by this provider.
    ManagedFresh,
}

impl WorkspacePlan {
    fn from_spec(spec: &SandboxSpec) -> Self {
        let Some(path) = &spec.working_directory else {
            return Self::ManagedFresh;
        };
        let path = PathBuf::from(path.as_str());
        if spec.workspace_ownership == Some(WorkspaceOwnership::Managed) {
            Self::ManagedNamed(path)
        } else {
            Self::Designated(path)
        }
    }

    /// The canonical path of a designated directory, when the plan names
    /// one that resolves. Only a designated directory is its own identity.
    async fn designated_directory(&self) -> Option<PathBuf> {
        match self {
            Self::Designated(path) => canonical_directory(path).await.ok(),
            Self::ManagedNamed(_) | Self::ManagedFresh => None,
        }
    }

    /// Makes the workspace exist and returns its canonical path with the
    /// ownership the record stores. `root` is the canonical registry root
    /// a fresh managed workspace lives under.
    async fn realize(self, root: &Path, id: &SandboxId) -> Result<(PathBuf, WorkspaceOwnership)> {
        match self {
            Self::Designated(path) => Ok((
                canonical_directory(&path).await?,
                WorkspaceOwnership::Designated,
            )),
            Self::ManagedNamed(path) => {
                tokio_fs::create_dir_all(&path)
                    .await
                    .map_err(|e| Error::io("creating managed host workspace", e))?;
                Ok((
                    canonical_directory(&path).await?,
                    WorkspaceOwnership::Managed,
                ))
            }
            Self::ManagedFresh => {
                let path = registry::resource_dir(root, id)?.join("workspace");
                tokio_fs::create_dir_all(&path).await.map_err(|error| {
                    Error::io(
                        format!("creating managed workspace {}", path.display()),
                        error,
                    )
                })?;
                let path = tokio_fs::canonicalize(&path).await.map_err(|error| {
                    Error::io(
                        format!("resolving managed workspace {}", path.display()),
                        error,
                    )
                })?;
                Ok((path, WorkspaceOwnership::Managed))
            }
        }
    }
}

/// Prefix of a sandbox id derived from a designated directory's path.
const DIRECTORY_ID_PREFIX: &str = "host-dir-";

/// The id a designated directory at canonical `path` is known by: the
/// path's bytes in hex, so the id stays inside the registry's character
/// set and the path can be read back. `None` when the encoded id would
/// exceed the id length limit; such a directory gets a fresh id and a
/// record instead.
///
/// A consumer that recorded only the directory can derive the id to
/// attach by; the path must already be canonical (see
/// [`HostProvider::directory_id`]).
fn directory_id(path: &Path) -> Option<SandboxId> {
    use std::fmt::Write as _;
    let mut id = String::from(DIRECTORY_ID_PREFIX);
    for byte in path.as_os_str().as_encoded_bytes() {
        let _ = write!(id, "{byte:02x}");
    }
    SandboxId::try_new(id).ok()
}

/// The directory a path-derived id names, when `id` has that shape.
fn directory_from_id(id: &SandboxId) -> Option<PathBuf> {
    let hex = id.as_str().strip_prefix(DIRECTORY_ID_PREFIX)?;
    if hex.is_empty() || hex.len() % 2 != 0 {
        return None;
    }
    let bytes = (0..hex.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&hex[index..index + 2], 16).ok())
        .collect::<Option<Vec<u8>>>()?;
    // SAFETY-free decode: the bytes came from `as_encoded_bytes` of a real
    // path on this platform, and a non-UTF-8 path is rejected rather than
    // reinterpreted.
    let text = String::from_utf8(bytes).ok()?;
    Some(PathBuf::from(text))
}

impl Default for HostProvider {
    fn default() -> Self {
        Self::new()
    }
}

fn host_capabilities() -> Capabilities {
    let mut caps = Capabilities::minimal(Isolation::None);
    caps.exec.live_streaming = true;
    caps.exec.streams_separated = true;
    caps.exec.stdin = true;
    caps.exec.stdin_stream = true;
    caps.exec.stop = true;
    caps.exec.stdio_process = true;
    caps.exec.environment = true;
    caps.fs.native = true;
    caps.fs.upload = true;
    caps.fs.download = true;
    caps.fs.permissions = true;
    caps.search.supported = true;
    caps.git.supported = true;
    caps.services.supported = true;
    // A port inside a host sandbox is a port on this machine.
    caps.access.preview_urls = true;
    caps
}

fn validate_supported_creation_fields(spec: &SandboxSpec) -> Result<()> {
    if spec.resources != Resources::default() {
        return Err(Error::invalid_spec(
            "resources",
            "the host provider does not manage compute resources",
        ));
    }
    if spec.user.is_some() {
        return Err(Error::invalid_spec(
            "user",
            "the host provider always runs as the calling user",
        ));
    }
    if !matches!(
        &spec.network,
        sandbox_driver::NetworkPolicy::ProviderDefault
    ) {
        return Err(Error::invalid_spec(
            "network",
            "the host provider does not manage host networking",
        ));
    }
    if spec.timers != LifecycleTimers::default() {
        return Err(Error::invalid_spec(
            "timers",
            "the host provider does not support lifecycle timers",
        ));
    }
    if spec.ephemeral {
        return Err(Error::invalid_spec(
            "ephemeral",
            "the host provider does not support stop-triggered deletion",
        ));
    }
    if spec.public.is_some() {
        return Err(Error::invalid_spec(
            "public",
            "the host provider does not manage public access",
        ));
    }
    if spec.region.is_some() {
        return Err(Error::invalid_spec(
            "region",
            "the host provider does not select a region",
        ));
    }
    if !spec.provider_config.is_null() {
        return Err(Error::invalid_spec(
            "provider_config",
            "the host provider has no provider-specific creation options",
        ));
    }
    if spec.sandbox_kind.is_some() {
        return Err(Error::invalid_spec(
            "sandbox_kind",
            "the host provider does not provision containers or virtual machines",
        ));
    }
    if !matches!(spec.source, SandboxSource::HostDirectory) {
        return Err(Error::invalid_spec(
            "source",
            "the host provider only supports SandboxSource::HostDirectory",
        ));
    }
    if !spec.volumes.is_empty() {
        return Err(Error::invalid_spec(
            "volumes",
            "the host provider has no volumes",
        ));
    }
    Ok(())
}

#[async_trait]
impl SandboxProvider for HostProvider {
    fn kind(&self) -> &ProviderKind {
        &self.kind
    }

    fn capabilities(&self) -> &Capabilities {
        &self.capabilities
    }

    async fn health(&self) -> Result<ProviderHealth> {
        // The host is its own backend; if this code runs, it is
        // reachable and authorized.
        Ok(ProviderHealth::new(HealthStatus::Ok))
    }

    #[tracing::instrument(skip_all, fields(provider_kind = %self.kind), err)]
    async fn create(
        &self,
        spec: &SandboxSpec,
        events: Option<EventContext>,
    ) -> Result<Arc<dyn Sandbox>> {
        spec.validate()?;
        validate_supported_creation_fields(spec)?;

        let emitter = EventEmitter::new(self.kind.clone(), events);
        let plan = WorkspacePlan::from_spec(spec);
        // A designated directory is its own identity: the id is derived from
        // the path, so a later process attaches to it without a record. A
        // path that does not resolve keeps a fresh id here and fails inside
        // the create operation below, where the failure is reported through
        // the events.
        let id = plan
            .designated_directory()
            .await
            .as_deref()
            .and_then(directory_id)
            .unwrap_or_else(|| {
                SandboxId::try_new(format!("host-{}", registry::fresh_id()))
                    .expect("generated id is valid")
            });
        if let Some(existing) = self.registry.lock().await.get(&id) {
            return Ok(Arc::clone(existing) as Arc<dyn Sandbox>);
        }
        let subject = EventSubject::Sandbox {
            id:   Some(id.clone()),
            name: spec.name.clone(),
        };
        let handle_emitter = emitter.clone();
        emitter
            .run(subject, Action::Create, |reporter| async move {
                reporter
                    .progress(Progress::new(ProgressCode::SANDBOX_PROVISION))
                    .await;
                registry::private_directory(&self.root).await?;
                let root = tokio_fs::canonicalize(&self.root)
                    .await
                    .map_err(|e| Error::io("resolving host registry", e))?;
                let (workspace, ownership) = plan.realize(&root, &id).await?;
                let record = Record {
                    version: 1,
                    id: id.clone(),
                    name: spec.name.clone(),
                    workspace,
                    ownership,
                    env: spec.env.clone(),
                    labels: spec.labels.clone(),
                    state: SandboxState::Running,
                    created_at: SystemTime::now(),
                };
                registry::write(&root, &record).await?;
                let mut handles = self.registry.lock().await;
                let sandbox = self.cache_handle(&mut handles, record, None, handle_emitter)?;
                Ok(sandbox as Arc<dyn Sandbox>)
            })
            .await
    }

    #[tracing::instrument(
        skip_all,
        fields(provider_kind = %self.kind, sandbox_id = %id),
        err
    )]
    async fn attach(
        &self,
        id: &SandboxId,
        events: Option<EventContext>,
    ) -> Result<Arc<dyn Sandbox>> {
        let emitter = EventEmitter::new(self.kind.clone(), events);
        let handle_emitter = emitter.clone();
        emitter
            .run(
                EventSubject::sandbox(Some(id.clone())),
                Action::Attach,
                |_| async move {
                    let sandbox = match self.load(id).await {
                        Ok(sandbox) => sandbox,
                        Err(Error::NotFound { .. }) => self.adopt_directory(id).await?,
                        Err(error) => return Err(error),
                    };
                    if *sandbox.state.lock().await == SandboxState::Deleted {
                        return Err(registry::missing(id));
                    }
                    Ok(Arc::new(sandbox.with_emitter(handle_emitter)) as Arc<dyn Sandbox>)
                },
            )
            .await
    }

    #[tracing::instrument(
        skip_all,
        fields(provider_kind = %self.kind, sandbox_id = %id),
        err
    )]
    async fn delete(&self, id: &SandboxId, events: Option<EventContext>) -> Result<()> {
        let sandbox = match self.load(id).await {
            Ok(sandbox) => sandbox,
            Err(Error::NotFound { .. }) => return Ok(()),
            Err(error) => return Err(error),
        };
        let handle = sandbox.with_emitter(EventEmitter::new(self.kind.clone(), events));
        handle.delete().await
    }

    #[tracing::instrument(
        skip_all,
        fields(provider_kind = %self.kind, label_count = filter.labels.len()),
        err
    )]
    async fn list(&self, filter: &SandboxFilter) -> Result<Vec<SandboxStatus>> {
        // Reading the records is enough to report sandboxes. Building
        // handles here would allocate process groups and cache a tombstone
        // for every resource the registry has ever held. An observed
        // registry's records follow this provider's own; a directory both
        // designate is reported once.
        let mut records = registry::records(&self.root).await?;
        if let Some(observed) = &self.observed {
            let own: HashSet<SandboxId> = records.iter().map(|record| record.id.clone()).collect();
            records.extend(
                registry::records(observed)
                    .await?
                    .into_iter()
                    .filter(|record| !own.contains(&record.id)),
            );
        }
        Ok(records
            .into_iter()
            .filter(|record| {
                record.state != SandboxState::Deleted
                    && filter
                        .labels
                        .iter()
                        .all(|(key, value)| record.labels.get(key) == Some(value))
            })
            .map(|record| record.status(record.state))
            .collect())
    }
}

/// A directory-backed sandbox on the local machine.
///
/// Lifecycle state has one owner per layer: `state` is the live value,
/// the registry record on disk is its durable copy, and `ProcessGroups`
/// admission is a projection of `state == Running`. All three change only
/// through [`Self::transition`], which holds the state lock for the whole
/// change.
///
/// A handle over an `observed` registry owns none of the three: the
/// record on disk is the owner's, read afresh on every `describe`, no
/// lifecycle change is admitted, and its process groups (the provider's
/// own) admit work regardless.
pub struct HostSandbox {
    registry:          Weak<HandleRegistry>,
    root:              PathBuf,
    /// The registry another process owns that the record was read from,
    /// which makes this handle read-only.
    observed:          Option<PathBuf>,
    groups:            Arc<ProcessGroups>,
    /// Identity and metadata as the registry stored them when this handle
    /// was built. Its `state` is that moment's value and is never updated;
    /// `state` below is the live one shared across attached handles, and
    /// `persist` writes the record with the live state in its place.
    record:            Record,
    capabilities:      Capabilities,
    state:             Arc<Mutex<SandboxState>>,
    /// Shared across attached handles.
    exec:              Arc<HostExec>,
    fs:                HostFs,
    events:            EventEmitter,
    working_directory: String,
}

impl HostSandbox {
    fn new(
        provider: &HostProvider,
        record: Record,
        observed: Option<PathBuf>,
        events: EventEmitter,
    ) -> Result<Self> {
        let root = provider.root.clone();
        let read_only = observed.is_some();
        let groups = Arc::new(ProcessGroups::new(
            registry::resource_dir(&root, &record.id)?.join("groups"),
            // The owner's state gates the owner's groups; a read-only
            // handle's groups are its own and admit work in any state.
            read_only || record.state == SandboxState::Running,
            provider.cleanup_on_drop,
        ));
        let exec = HostExec::with_groups(
            record.workspace.clone(),
            record.env.clone(),
            // Recreating a vanished managed workspace is the owner's call.
            !read_only && record.ownership == WorkspaceOwnership::Managed,
            groups.clone(),
        );
        Ok(Self {
            registry: Arc::downgrade(&provider.registry),
            root,
            observed,
            groups,
            capabilities: provider.capabilities.clone(),
            working_directory: record.workspace.to_string_lossy().into_owned(),
            fs: HostFs::new(record.workspace.clone()),
            state: Arc::new(Mutex::new(record.state)),
            record,
            exec: Arc::new(exec),
            events,
        })
    }

    async fn persist(&self, state: SandboxState) -> Result<()> {
        registry::write(&self.root, &Record {
            state,
            ..self.record.clone()
        })
        .await
    }

    fn with_emitter(&self, events: EventEmitter) -> Self {
        Self {
            registry: self.registry.clone(),
            root: self.root.clone(),
            observed: self.observed.clone(),
            groups: self.groups.clone(),
            record: self.record.clone(),
            capabilities: self.capabilities.clone(),
            state: Arc::clone(&self.state),
            exec: Arc::clone(&self.exec),
            fs: HostFs::new(self.record.workspace.clone()),
            events,
            working_directory: self.working_directory.clone(),
        }
    }

    /// The workspace directory on the local filesystem.
    pub fn workspace(&self) -> &Path {
        &self.record.workspace
    }

    async fn remove_cached_handle(&self) {
        if let Some(registry) = self.registry.upgrade() {
            registry.lock().await.remove(&self.record.id);
        }
    }

    /// Drives one lifecycle change to `target` under the `action` events.
    /// This is the only place the three copies of lifecycle state move:
    /// it holds the state lock for the whole change, applies the
    /// idempotency rule for a deleted sandbox, changes `ProcessGroups`
    /// admission to match `target`, runs `work`, persists the record, sets
    /// the live state, and evicts a deleted handle from the cache.
    ///
    /// A deleted sandbox cannot start again (it is reported missing), while
    /// stopping or deleting it again succeeds and only drops the cached
    /// handle. A read-only handle refuses every change before touching
    /// any of the three.
    ///
    /// When `work` or the persist fails after admission moved, admission is
    /// moved back to match the unchanged live state, so a sandbox that still
    /// reports `Running` admits work and one that reports `Stopped` refuses
    /// it, and the caller can retry the whole change. Work that a failed
    /// stop already fenced stays fenced.
    async fn transition(
        &self,
        action: Action,
        target: SandboxState,
        work: impl AsyncFnOnce() -> Result<()>,
    ) -> Result<()> {
        self.events
            .run(
                EventSubject::sandbox(Some(self.record.id.clone())),
                action,
                |_| async {
                    if self.observed.is_some() {
                        return Err(Error::ReadOnly {
                            resource: ResourceKind::Sandbox,
                            id: self.record.id.as_str().to_owned(),
                            action,
                        });
                    }
                    let mut state = self.state.lock().await;
                    if *state == SandboxState::Deleted {
                        if target == SandboxState::Running {
                            return Err(registry::missing(&self.record.id));
                        }
                        drop(state);
                        self.remove_cached_handle().await;
                        return Ok(());
                    }
                    self.admit_work(target == SandboxState::Running).await?;
                    let outcome = async {
                        work().await?;
                        self.persist(target).await
                    }
                    .await;
                    if let Err(error) = outcome {
                        if let Err(rollback) =
                            self.admit_work(*state == SandboxState::Running).await
                        {
                            tracing::warn!(
                                provider_kind = "host",
                                sandbox_id = %self.record.id,
                                error = %rollback,
                                "restoring process admission after a failed lifecycle change"
                            );
                        }
                        return Err(error);
                    }
                    *state = target;
                    if target == SandboxState::Deleted {
                        // Persisted tombstones remain available for recovery
                        // policy, but deleted resources need no cached handle.
                        drop(state);
                        self.remove_cached_handle().await;
                    }
                    Ok(())
                },
            )
            .await
    }

    /// Moves `ProcessGroups` admission to match a `Running` (`true`) or
    /// non-running (`false`) live state. Refusing admission fences every
    /// group the sandbox owns.
    async fn admit_work(&self, running: bool) -> Result<()> {
        if running {
            self.groups.start().await
        } else {
            self.groups.stop().await
        }
    }

    /// Removes a managed workspace; a designated directory is never
    /// touched. A workspace that is already gone is not an error.
    async fn remove_managed_workspace(&self) -> Result<()> {
        if self.record.ownership != WorkspaceOwnership::Managed {
            return Ok(());
        }
        match tokio_fs::remove_dir_all(&self.record.workspace).await {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(Error::io(
                format!(
                    "removing managed workspace {}",
                    self.record.workspace.display()
                ),
                error,
            )),
        }
    }

    /// The sandbox as reported: the live state for an owned sandbox, the
    /// owner's current record for an observed one, so the owner's later
    /// changes show through the handle.
    async fn status(&self) -> Result<SandboxStatus> {
        if let Some(observed) = &self.observed {
            let record = registry::read(observed, &self.record.id).await?;
            return Ok(record.status(record.state));
        }
        Ok(self.record.status(*self.state.lock().await))
    }
}

#[async_trait]
impl Sandbox for HostSandbox {
    fn id(&self) -> &SandboxId {
        &self.record.id
    }

    fn capabilities(&self) -> &Capabilities {
        &self.capabilities
    }

    #[tracing::instrument(skip_all, fields(provider_kind = "host", sandbox_id = %self.record.id), err)]
    async fn describe(&self) -> Result<SandboxStatus> {
        self.status().await
    }

    fn working_directory(&self) -> &str {
        &self.working_directory
    }

    async fn environment(&self) -> Result<BTreeMap<String, String>> {
        Ok(effective_env(&self.record.env))
    }

    #[tracing::instrument(skip_all, fields(provider_kind = "host", sandbox_id = %self.record.id), err)]
    async fn platform_info(&self) -> Result<PlatformInfo> {
        let version = self
            .exec
            .run(
                &ExecSpec::new("uname")
                    .arg("-r")
                    .timeout(Duration::from_secs(10)),
            )
            .await
            .map(|result| result.stdout_lossy().trim().to_owned())
            .unwrap_or_default();
        Ok(PlatformInfo::new(
            env::consts::OS,
            env::consts::ARCH,
            version,
        ))
    }

    /// Permit work after a successful stop, preserving the workspace.
    #[tracing::instrument(skip_all, fields(provider_kind = "host", sandbox_id = %self.record.id), err)]
    async fn start(&self) -> Result<()> {
        self.transition(Action::Start, SandboxState::Running, async || Ok(()))
            .await
    }

    /// End this sandbox's work while retaining its workspace.
    #[tracing::instrument(skip_all, fields(provider_kind = "host", sandbox_id = %self.record.id), err)]
    async fn stop(&self) -> Result<()> {
        self.transition(Action::Stop, SandboxState::Stopped, async || Ok(()))
            .await
    }

    #[tracing::instrument(skip_all, fields(provider_kind = "host", sandbox_id = %self.record.id), err)]
    async fn delete(&self) -> Result<()> {
        self.transition(Action::Delete, SandboxState::Deleted, async || {
            self.remove_managed_workspace().await
        })
        .await
    }

    fn exec(&self) -> &dyn Exec {
        &*self.exec
    }

    fn fs(&self) -> &dyn Filesystem {
        &self.fs
    }

    fn preview_urls(&self) -> Option<&dyn PreviewUrls> {
        Some(&HostPreview)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn deleted_handles_leave_the_cache_without_removing_tombstones() {
        let provider = HostProvider::new();
        for _ in 0..100 {
            let sandbox = provider
                .create(&SandboxSpec::new(SandboxSource::HostDirectory), None)
                .await
                .expect("create");
            let attached = provider.attach(sandbox.id(), None).await.expect("attach");
            let workspace = sandbox.working_directory().to_owned();
            attached
                .delete()
                .await
                .expect("delete through another handle");
            assert!(provider.registry.lock().await.is_empty());
            assert!(!Path::new(&workspace).exists());
            assert_eq!(
                sandbox.describe().await.expect("shared state").state,
                SandboxState::Deleted
            );
            let record = registry::read(&provider.root, sandbox.id())
                .await
                .expect("durable tombstone");
            assert_eq!(record.state, SandboxState::Deleted);
            assert!(matches!(
                provider.attach(sandbox.id(), None).await,
                Err(Error::NotFound { .. })
            ));
            provider
                .delete(sandbox.id(), None)
                .await
                .expect("idempotent provider delete");
            assert!(provider.registry.lock().await.is_empty());
        }
        tokio_fs::remove_dir_all(&provider.root)
            .await
            .expect("test registry cleanup");
    }
}
