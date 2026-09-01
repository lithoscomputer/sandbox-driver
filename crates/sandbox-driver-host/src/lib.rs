//! Host (local) sandbox provider.
//!
//! The base case of the provider family: sandboxes are directories on the
//! local machine, commands run as the calling user, and there is **no
//! isolation boundary** — the provider declares `Isolation::None`.
//!
//! A workspace is either **designated** (a caller-owned directory named in
//! `SandboxSpec::working_directory`; `delete` releases the handle and never
//! touches its contents) or **managed** (a temporary directory this crate
//! creates and removes on `delete`).
//!
//! # Runtime behavior
//!
//! Async on Tokio; the caller owns the runtime. This crate spawns tasks
//! only for stream pumping inside a running `exec` call and the stderr
//! tail reader of a spawned stdio process; both end when their process
//! ends. `start`/`stop` are no-ops (the host is always running) and
//! sandbox handles live in an in-process registry — they do not survive a
//! process restart.

mod exec;
mod fs;

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::{env, io, process};

use async_trait::async_trait;
use sandbox_driver::{
    Action, Capabilities, Error, EventContext, EventEmitter, EventSubject, Exec, ExecSpec,
    Filesystem, HealthStatus, Isolation, LifecycleTimers, PlatformInfo, Progress, ProgressCode,
    ProviderHealth, ProviderKind, ResourceKind, Resources, Result, Sandbox, SandboxFilter,
    SandboxId, SandboxProvider, SandboxSource, SandboxSpec, SandboxState, SandboxStatus,
    WorkspaceOwnership,
};
use tokio::fs as tokio_fs;

pub use crate::exec::HostExec;
pub use crate::fs::HostFs;

/// The host provider. Create one per process and share it.
pub struct HostProvider {
    kind:         ProviderKind,
    capabilities: Capabilities,
    registry:     Mutex<HashMap<SandboxId, Arc<HostSandbox>>>,
    counter:      AtomicU64,
}

impl HostProvider {
    pub fn new() -> Self {
        Self {
            kind:         ProviderKind::try_new("host").expect("static kind is valid"),
            capabilities: host_capabilities(),
            registry:     Mutex::new(HashMap::new()),
            counter:      AtomicU64::new(0),
        }
    }

    fn next_id(&self) -> SandboxId {
        let count = self.counter.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.subsec_nanos());
        let id = format!("host-{}-{count}-{nanos:x}", process::id());
        SandboxId::try_new(id).expect("generated id is valid")
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
    caps.exec.cancel = true;
    caps.exec.stdio_process = true;
    caps.fs.native = true;
    caps.fs.upload = true;
    caps.fs.download = true;
    caps.fs.permissions = true;
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
        let id = self.next_id();
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
                let (workspace, ownership) = if let Some(path) = &spec.working_directory {
                    let path = PathBuf::from(path.as_str());
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
                    (path, WorkspaceOwnership::Designated)
                } else {
                    let path = env::temp_dir()
                        .join("sandbox-driver-host")
                        .join(id.as_str());
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
                let sandbox = Arc::new(HostSandbox::new(
                    id.clone(),
                    spec.name.clone(),
                    self.capabilities.clone(),
                    workspace,
                    ownership,
                    spec.env.clone(),
                    spec.labels.clone(),
                    handle_emitter,
                ));
                self.registry
                    .lock()
                    .expect("registry lock")
                    .insert(id, Arc::clone(&sandbox));
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
                    let registry = self.registry.lock().expect("registry lock");
                    registry
                        .get(id)
                        .map(|sandbox| {
                            Arc::new(sandbox.with_emitter(handle_emitter)) as Arc<dyn Sandbox>
                        })
                        .ok_or_else(|| Error::NotFound {
                            resource: ResourceKind::Sandbox,
                            id:       id.as_str().to_owned(),
                        })
                },
            )
            .await
    }

    #[tracing::instrument(
        skip_all,
        fields(provider_kind = %self.kind, label_count = filter.labels.len()),
        err
    )]
    async fn list(&self, filter: &SandboxFilter) -> Result<Vec<SandboxStatus>> {
        let sandboxes: Vec<Arc<HostSandbox>> = self
            .registry
            .lock()
            .expect("registry lock")
            .values()
            .cloned()
            .collect();
        let mut statuses = Vec::new();
        for sandbox in sandboxes {
            let status = sandbox.status();
            let matches = filter
                .labels
                .iter()
                .all(|(key, value)| status.labels.get(key) == Some(value));
            if matches {
                statuses.push(status);
            }
        }
        Ok(statuses)
    }
}

/// A directory-backed sandbox on the local machine.
pub struct HostSandbox {
    id:                SandboxId,
    name:              Option<String>,
    capabilities:      Capabilities,
    workspace:         PathBuf,
    ownership:         WorkspaceOwnership,
    labels:            BTreeMap<String, String>,
    state:             Arc<Mutex<SandboxState>>,
    env:               BTreeMap<String, String>,
    exec:              HostExec,
    fs:                HostFs,
    events:            EventEmitter,
    working_directory: String,
    created_at:        SystemTime,
}

impl HostSandbox {
    fn new(
        id: SandboxId,
        name: Option<String>,
        capabilities: Capabilities,
        workspace: PathBuf,
        ownership: WorkspaceOwnership,
        env: BTreeMap<String, String>,
        labels: BTreeMap<String, String>,
        events: EventEmitter,
    ) -> Self {
        let working_directory = workspace.to_string_lossy().into_owned();
        Self {
            id,
            name,
            capabilities,
            exec: HostExec::new(workspace.clone(), env.clone()),
            fs: HostFs::new(workspace.clone()),
            workspace,
            ownership,
            labels,
            state: Arc::new(Mutex::new(SandboxState::Running)),
            env,
            events,
            working_directory,
            created_at: SystemTime::now(),
        }
    }

    fn with_emitter(&self, events: EventEmitter) -> Self {
        Self {
            id: self.id.clone(),
            name: self.name.clone(),
            capabilities: self.capabilities.clone(),
            workspace: self.workspace.clone(),
            ownership: self.ownership,
            labels: self.labels.clone(),
            state: Arc::clone(&self.state),
            env: self.env.clone(),
            exec: HostExec::new(self.workspace.clone(), self.env.clone()),
            fs: HostFs::new(self.workspace.clone()),
            events,
            working_directory: self.working_directory.clone(),
            created_at: self.created_at,
        }
    }

    /// The workspace directory on the local filesystem.
    pub fn workspace(&self) -> &Path {
        &self.workspace
    }

    fn status(&self) -> SandboxStatus {
        let state = *self.state.lock().expect("state lock");
        let mut status = SandboxStatus::new(self.id.clone(), state);
        status.name.clone_from(&self.name);
        status.provider_state = format!("{state:?}").to_lowercase();
        status.labels = self.labels.clone();
        status.workspace_ownership = Some(self.ownership);
        status.created_at = Some(self.created_at);
        status
    }
}

#[async_trait]
impl Sandbox for HostSandbox {
    fn id(&self) -> &SandboxId {
        &self.id
    }

    fn capabilities(&self) -> &Capabilities {
        &self.capabilities
    }

    #[tracing::instrument(skip_all, fields(provider_kind = "host", sandbox_id = %self.id), err)]
    async fn describe(&self) -> Result<SandboxStatus> {
        Ok(self.status())
    }

    fn working_directory(&self) -> &str {
        &self.working_directory
    }

    #[tracing::instrument(skip_all, fields(provider_kind = "host", sandbox_id = %self.id), err)]
    async fn platform_info(&self) -> Result<PlatformInfo> {
        let version = self
            .exec
            .run(&ExecSpec::new("uname -r").timeout(Duration::from_secs(10)))
            .await
            .map(|result| result.stdout_lossy().trim().to_owned())
            .unwrap_or_default();
        Ok(PlatformInfo::new(
            env::consts::OS,
            env::consts::ARCH,
            version,
        ))
    }

    /// No-op: the host is always running.
    #[tracing::instrument(skip_all, fields(provider_kind = "host", sandbox_id = %self.id), err)]
    async fn start(&self) -> Result<()> {
        self.events
            .run(
                EventSubject::sandbox(Some(self.id.clone())),
                Action::Start,
                |_| async { Ok(()) },
            )
            .await
    }

    /// No-op: stopping the caller's own machine is not this crate's job.
    #[tracing::instrument(skip_all, fields(provider_kind = "host", sandbox_id = %self.id), err)]
    async fn stop(&self) -> Result<()> {
        self.events
            .run(
                EventSubject::sandbox(Some(self.id.clone())),
                Action::Stop,
                |_| async { Ok(()) },
            )
            .await
    }

    #[tracing::instrument(skip_all, fields(provider_kind = "host", sandbox_id = %self.id), err)]
    async fn delete(&self) -> Result<()> {
        self.events
            .run(
                EventSubject::sandbox(Some(self.id.clone())),
                Action::Delete,
                |_| async {
                    if *self.state.lock().expect("state lock") == SandboxState::Deleted {
                        return Ok(());
                    }
                    if self.ownership == WorkspaceOwnership::Managed {
                        match tokio_fs::remove_dir_all(&self.workspace).await {
                            Ok(()) => {}
                            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                            Err(error) => {
                                return Err(Error::io(
                                    format!(
                                        "removing managed workspace {}",
                                        self.workspace.display()
                                    ),
                                    error,
                                ));
                            }
                        }
                    }
                    *self.state.lock().expect("state lock") = SandboxState::Deleted;
                    Ok(())
                },
            )
            .await
    }

    fn exec(&self) -> &dyn Exec {
        &self.exec
    }

    fn fs(&self) -> &dyn Filesystem {
        &self.fs
    }
}
