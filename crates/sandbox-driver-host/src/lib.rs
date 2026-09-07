//! Host (local) sandbox provider.
//!
//! Internal provider implementation, shared by the plugin executable and tests.
//! Applications use this provider through JSON-RPC, via
//! `sandbox-driver-protocol`.
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
//! Temporary providers end owned process groups when their last owner drops.
//! Caller-owned registries retain groups for explicit stop or recovery.

mod access;
mod exec;
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod fence;
mod fs;
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod observation;
mod registry;

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Weak};
use std::time::{Duration, SystemTime};
use std::{env, io};

use async_trait::async_trait;
use sandbox_driver::{
    Action, Capabilities, Error, EventContext, EventEmitter, EventSubject, Exec, ExecSpec,
    Filesystem, HealthStatus, Isolation, LifecycleTimers, PlatformInfo, PreviewUrls, Progress,
    ProgressCode, ProviderHealth, ProviderKind, Resources, Result, Sandbox, SandboxFilter,
    SandboxId, SandboxProvider, SandboxSource, SandboxSpec, SandboxState, SandboxStatus,
    WorkspaceOwnership,
};
use tokio::fs as tokio_fs;
use tokio::sync::Mutex;

use crate::access::HostPreview;
pub use crate::exec::HostExec;
use crate::exec::effective_env;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use crate::fence::ProcessGroups;
pub use crate::fs::HostFs;
use crate::registry::Record;

type HandleRegistry = Mutex<HashMap<SandboxId, Arc<HostSandbox>>>;

/// A directory-backed provider. Use [`Self::with_registry`] to preserve
/// sandbox identity across provider or plugin restarts.
pub struct HostProvider {
    kind:            ProviderKind,
    capabilities:    Capabilities,
    root:            PathBuf,
    cleanup_on_drop: bool,
    registry:        Arc<HandleRegistry>,
}

impl HostProvider {
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

    fn at(root: PathBuf, cleanup_on_drop: bool) -> Self {
        Self {
            kind: ProviderKind::try_new("host").expect("static kind is valid"),
            capabilities: host_capabilities(),
            root,
            cleanup_on_drop,
            registry: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    async fn load(&self, id: &SandboxId) -> Result<Arc<HostSandbox>> {
        let mut registry = self.registry.lock().await;
        if let Some(sandbox) = registry.get(id) {
            return Ok(sandbox.clone());
        }
        let record = registry::read(&self.root, id).await?;
        if record.state == SandboxState::Deleted {
            return Err(registry::missing(id));
        }
        let sandbox = Arc::new(HostSandbox::new(
            record,
            self.root.clone(),
            self.capabilities.clone(),
            EventEmitter::new(self.kind.clone(), None),
            self.cleanup_on_drop,
            Arc::downgrade(&self.registry),
        )?);
        registry.insert(id.clone(), sandbox.clone());
        Ok(sandbox)
    }
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

        let emitter = EventEmitter::new(self.kind.clone(), events);
        let id = SandboxId::try_new(format!("host-{}", registry::fresh_id()))
            .expect("generated id is valid");
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
                let (workspace, ownership) = if let Some(path) = &spec.working_directory {
                    let path = PathBuf::from(path.as_str());
                    let ownership = spec
                        .workspace_ownership
                        .unwrap_or(WorkspaceOwnership::Designated);
                    if ownership == WorkspaceOwnership::Managed {
                        tokio_fs::create_dir_all(&path)
                            .await
                            .map_err(|e| Error::io("creating managed host workspace", e))?;
                    }
                    let metadata = tokio_fs::metadata(&path).await.map_err(|error| {
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
                    let path = tokio_fs::canonicalize(&path).await.map_err(|error| {
                        Error::io(
                            format!("resolving designated directory {}", path.display()),
                            error,
                        )
                    })?;
                    (path, ownership)
                } else {
                    let path = registry::resource_dir(&root, &id)?.join("workspace");
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
                    (path, WorkspaceOwnership::Managed)
                };
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
                let sandbox = Arc::new(HostSandbox::new(
                    record,
                    root,
                    self.capabilities.clone(),
                    handle_emitter,
                    self.cleanup_on_drop,
                    Arc::downgrade(&self.registry),
                )?);
                self.registry.lock().await.insert(id, sandbox.clone());
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
                    let sandbox = self.load(id).await?;
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
        let mut entries = match tokio_fs::read_dir(&self.root).await {
            Ok(entries) => entries,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(Error::io("listing host registry", e)),
        };
        let mut statuses = Vec::new();
        while let Some(entry) = entries
            .next_entry()
            .await
            .map_err(|e| Error::io("reading host registry entry", e))?
        {
            if !entry
                .file_type()
                .await
                .map_err(|e| Error::io("reading registry entry type", e))?
                .is_dir()
            {
                continue;
            }
            let Ok(id) = SandboxId::try_new(entry.file_name().to_string_lossy().into_owned())
            else {
                continue;
            };
            // Reading the record is enough to report a sandbox. Building a
            // handle here would allocate process groups and cache a tombstone
            // for every resource the registry has ever held.
            let record = match registry::read(&self.root, &id).await {
                Ok(record) => record,
                Err(Error::NotFound { .. }) => continue,
                Err(error) => return Err(error),
            };
            if record.state != SandboxState::Deleted
                && filter
                    .labels
                    .iter()
                    .all(|(key, value)| record.labels.get(key) == Some(value))
            {
                statuses.push(record.status(record.state));
            }
        }
        Ok(statuses)
    }
}

/// A directory-backed sandbox on the local machine.
pub struct HostSandbox {
    registry:          Weak<HandleRegistry>,
    root:              PathBuf,
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    groups:            Arc<ProcessGroups>,
    /// Identity and metadata exactly as the registry stores them. Its
    /// `state` is the value last written to disk; `state` below is the
    /// live one shared across attached handles.
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
        record: Record,
        root: PathBuf,
        capabilities: Capabilities,
        events: EventEmitter,
        cleanup_on_drop: bool,
        registry: Weak<HandleRegistry>,
    ) -> Result<Self> {
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        let _ = cleanup_on_drop;
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        let groups = Arc::new(ProcessGroups::new(
            registry::resource_dir(&root, &record.id)?.join("groups"),
            record.state == SandboxState::Running,
            cleanup_on_drop,
        ));
        let exec = HostExec::with_groups(
            record.workspace.clone(),
            record.env.clone(),
            record.ownership == WorkspaceOwnership::Managed,
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            groups.clone(),
        );
        Ok(Self {
            registry,
            root,
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            groups,
            capabilities,
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
            #[cfg(any(target_os = "linux", target_os = "macos"))]
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

    async fn status(&self) -> SandboxStatus {
        self.record.status(*self.state.lock().await)
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
        Ok(self.status().await)
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
        self.events
            .run(
                EventSubject::sandbox(Some(self.record.id.clone())),
                Action::Start,
                |_| async {
                    let mut state = self.state.lock().await;
                    if *state == SandboxState::Deleted {
                        return Err(registry::missing(&self.record.id));
                    }
                    #[cfg(any(target_os = "linux", target_os = "macos"))]
                    self.groups.start().await?;
                    self.persist(SandboxState::Running).await?;
                    *state = SandboxState::Running;
                    Ok(())
                },
            )
            .await
    }

    /// End this sandbox's work while retaining its workspace.
    #[tracing::instrument(skip_all, fields(provider_kind = "host", sandbox_id = %self.record.id), err)]
    async fn stop(&self) -> Result<()> {
        self.events
            .run(
                EventSubject::sandbox(Some(self.record.id.clone())),
                Action::Stop,
                |_| async {
                    let mut state = self.state.lock().await;
                    if *state == SandboxState::Deleted {
                        drop(state);
                        self.remove_cached_handle().await;
                        return Ok(());
                    }
                    #[cfg(any(target_os = "linux", target_os = "macos"))]
                    self.groups.stop().await?;
                    self.persist(SandboxState::Stopped).await?;
                    *state = SandboxState::Stopped;
                    Ok(())
                },
            )
            .await
    }

    #[tracing::instrument(skip_all, fields(provider_kind = "host", sandbox_id = %self.record.id), err)]
    async fn delete(&self) -> Result<()> {
        self.events
            .run(
                EventSubject::sandbox(Some(self.record.id.clone())),
                Action::Delete,
                |_| async {
                    let mut state = self.state.lock().await;
                    if *state == SandboxState::Deleted {
                        drop(state);
                        self.remove_cached_handle().await;
                        return Ok(());
                    }
                    #[cfg(any(target_os = "linux", target_os = "macos"))]
                    self.groups.stop().await?;
                    if self.record.ownership == WorkspaceOwnership::Managed {
                        match tokio_fs::remove_dir_all(&self.record.workspace).await {
                            Ok(()) => {}
                            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                            Err(error) => {
                                return Err(Error::io(
                                    format!(
                                        "removing managed workspace {}",
                                        self.record.workspace.display()
                                    ),
                                    error,
                                ));
                            }
                        }
                    }
                    self.persist(SandboxState::Deleted).await?;
                    *state = SandboxState::Deleted;
                    // Persisted tombstones remain available for recovery
                    // policy, but deleted resources need no cached handle.
                    drop(state);
                    self.remove_cached_handle().await;
                    Ok(())
                },
            )
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
