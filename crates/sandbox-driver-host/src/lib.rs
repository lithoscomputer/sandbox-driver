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
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use std::{env, io, process};

use async_trait::async_trait;
use sandbox_driver::{
    Capabilities, Error, EventCallback, EventDispatcher, Exec, ExecSpec, Filesystem, Isolation,
    LifecycleAction, PlatformInfo, ProviderKind, ResourceKind, Result, Sandbox, SandboxEvent,
    SandboxFilter, SandboxId, SandboxProvider, SandboxSource, SandboxSpec, SandboxState,
    SandboxStatus, WorkspaceOwnership,
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

#[async_trait]
impl SandboxProvider for HostProvider {
    fn kind(&self) -> &ProviderKind {
        &self.kind
    }

    fn capabilities(&self) -> &Capabilities {
        &self.capabilities
    }

    async fn create(
        &self,
        spec: &SandboxSpec,
        events: Option<EventCallback>,
    ) -> Result<Arc<dyn Sandbox>> {
        spec.validate()?;
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

        let dispatcher = events.map(EventDispatcher::new);
        if let Some(dispatcher) = &dispatcher {
            dispatcher
                .emit(SandboxEvent::ActionStarted {
                    action: LifecycleAction::Create,
                })
                .await;
        }
        let started = Instant::now();

        let id = self.next_id();
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
            (path, WorkspaceOwnership::Managed)
        };

        let sandbox = Arc::new(HostSandbox::new(
            id.clone(),
            self.capabilities.clone(),
            workspace,
            ownership,
            spec.env.clone(),
            spec.labels.clone(),
            dispatcher,
        ));
        self.registry
            .lock()
            .expect("registry lock")
            .insert(id, Arc::clone(&sandbox));

        if let Some(dispatcher) = &sandbox.dispatcher {
            dispatcher
                .emit(SandboxEvent::ActionCompleted {
                    action:   LifecycleAction::Create,
                    duration: started.elapsed(),
                })
                .await;
        }
        Ok(sandbox)
    }

    async fn attach(
        &self,
        id: &SandboxId,
        _events: Option<EventCallback>,
    ) -> Result<Arc<dyn Sandbox>> {
        let registry = self.registry.lock().expect("registry lock");
        registry
            .get(id)
            .cloned()
            .map(|sandbox| sandbox as Arc<dyn Sandbox>)
            .ok_or_else(|| Error::NotFound {
                resource: ResourceKind::Sandbox,
                id:       id.as_str().to_owned(),
            })
    }

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
    capabilities:      Capabilities,
    workspace:         PathBuf,
    ownership:         WorkspaceOwnership,
    labels:            BTreeMap<String, String>,
    state:             Mutex<SandboxState>,
    exec:              HostExec,
    fs:                HostFs,
    dispatcher:        Option<EventDispatcher>,
    working_directory: String,
    created_at:        SystemTime,
}

impl HostSandbox {
    fn new(
        id: SandboxId,
        capabilities: Capabilities,
        workspace: PathBuf,
        ownership: WorkspaceOwnership,
        env: BTreeMap<String, String>,
        labels: BTreeMap<String, String>,
        dispatcher: Option<EventDispatcher>,
    ) -> Self {
        let working_directory = workspace.to_string_lossy().into_owned();
        Self {
            id,
            capabilities,
            exec: HostExec::new(workspace.clone(), env),
            fs: HostFs::new(workspace.clone()),
            workspace,
            ownership,
            labels,
            state: Mutex::new(SandboxState::Running),
            dispatcher,
            working_directory,
            created_at: SystemTime::now(),
        }
    }

    /// The workspace directory on the local filesystem.
    pub fn workspace(&self) -> &Path {
        &self.workspace
    }

    fn status(&self) -> SandboxStatus {
        let state = *self.state.lock().expect("state lock");
        let mut status = SandboxStatus::new(self.id.clone(), state);
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

    async fn describe(&self) -> Result<SandboxStatus> {
        Ok(self.status())
    }

    fn working_directory(&self) -> &str {
        &self.working_directory
    }

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
    async fn start(&self) -> Result<()> {
        Ok(())
    }

    /// No-op: stopping the caller's own machine is not this crate's job.
    async fn stop(&self) -> Result<()> {
        Ok(())
    }

    async fn delete(&self) -> Result<()> {
        {
            let mut state = self.state.lock().expect("state lock");
            if *state == SandboxState::Deleted {
                return Ok(());
            }
            *state = SandboxState::Deleted;
        }
        if let Some(dispatcher) = &self.dispatcher {
            dispatcher
                .emit(SandboxEvent::ActionStarted {
                    action: LifecycleAction::Delete,
                })
                .await;
        }
        let started = Instant::now();
        if self.ownership == WorkspaceOwnership::Managed {
            match tokio_fs::remove_dir_all(&self.workspace).await {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(Error::io(
                        format!("removing managed workspace {}", self.workspace.display()),
                        error,
                    ));
                }
            }
        }
        if let Some(dispatcher) = &self.dispatcher {
            dispatcher
                .emit(SandboxEvent::ActionCompleted {
                    action:   LifecycleAction::Delete,
                    duration: started.elapsed(),
                })
                .await;
        }
        Ok(())
    }

    fn exec(&self) -> &dyn Exec {
        &self.exec
    }

    fn fs(&self) -> &dyn Filesystem {
        &self.fs
    }
}
