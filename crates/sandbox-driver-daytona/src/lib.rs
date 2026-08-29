//! Daytona cloud sandbox provider.
//!
//! VM-backed sandboxes (`Isolation::Vm`) through the Daytona control
//! plane and per-sandbox toolbox daemon, with snapshots and volumes as
//! first-class services and preview-URL/SSH access facets.
//!
//! Protocol v1 scope, wrapped-SDK surface only: archive, resize, recover,
//! refresh-activity, timers, and labels are supported; pause/resume,
//! fork, checkpoints, live-sandbox snapshots, and runtime network updates
//! are not declared and return `Unsupported`. Exec is buffered through
//! the toolbox and reports `live_streaming: false` /
//! `streams_separated: false` honestly.
//!
//! # Configuration
//!
//! [`DaytonaProvider::connect`] uses the SDK's environment configuration:
//! `DAYTONA_API_KEY` (or `DAYTONA_JWT_TOKEN` + `DAYTONA_ORGANIZATION_ID`),
//! optional `DAYTONA_API_URL` and `DAYTONA_TARGET`.

mod access;
mod exec;
mod fs;

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use daytona_api_client::models::{
    SnapshotState as ApiSnapshotState, VolumeDto, VolumeState as ApiVolumeState,
};
use daytona_sdk::{
    Client, CreateParams, CreateSandboxOptions, CreateSnapshotParams, DaytonaError, DockerImage,
    ImageParams, ImageSource, SandboxBaseParams, SnapshotParams,
};
use sandbox_driver::{
    Capabilities, Error, ErrorReport, EventCallback, EventDispatcher, Exec, ExecSpec, Filesystem,
    Isolation, LifecycleAction, LifecycleTimers, NetworkPolicy, PlatformInfo, PreviewUrls,
    ProviderError, ProviderKind, ResourceKind, Resources, Result, Sandbox, SandboxEvent,
    SandboxFilter, SandboxId, SandboxProvider, SandboxSource, SandboxSpec, SandboxState,
    SandboxStatus, SnapshotCaps, SnapshotFilter, SnapshotId, SnapshotService, SnapshotSource,
    SnapshotSpec, SnapshotState, SnapshotStatus, SshAccess, VolumeCaps, VolumeId, VolumeService,
    VolumeSpec, VolumeState, VolumeStatus,
};

pub use crate::access::DaytonaAccess;
pub use crate::exec::DaytonaExec;
pub use crate::fs::DaytonaFs;

const MANAGED_LABEL: &str = "sh.sandbox-driver.managed";
const FALLBACK_WORKING_DIR: &str = "/home/daytona";
const CREATE_TIMEOUT: Duration = Duration::from_secs(600);

pub(crate) type DaytonaClient = Arc<Client>;

pub(crate) fn shell_quote(value: &str) -> String {
    let mut quoted = String::with_capacity(value.len() + 2);
    quoted.push('\'');
    for c in value.chars() {
        if c == '\'' {
            quoted.push_str("'\\''");
        } else {
            quoted.push(c);
        }
    }
    quoted.push('\'');
    quoted
}

pub(crate) fn is_not_found(error: &DaytonaError) -> bool {
    matches!(error, DaytonaError::NotFound { .. })
}

pub(crate) fn daytona_error(context: &str, error: &DaytonaError) -> Error {
    let kind = ProviderKind::try_new("daytona").expect("static kind is valid");
    match error {
        DaytonaError::RateLimit { .. } => Error::RateLimited { retry_after: None },
        DaytonaError::NotFound { message, .. } => Error::Provider({
            let mut provider = ProviderError::new(kind, format!("{context}: {message}"));
            provider.code = Some("404".to_owned());
            provider
        }),
        other => {
            let mut provider = ProviderError::new(kind, format!("{context}: {other}"));
            if let DaytonaError::Api { status_code, .. } = other {
                provider.code = Some(status_code.to_string());
                provider.retryable = *status_code >= 500;
            }
            Error::Provider(provider)
        }
    }
}

fn map_state(state: Option<daytona_sdk::SandboxState>) -> SandboxState {
    use daytona_sdk::SandboxState as Ds;
    match state {
        None => SandboxState::Unknown,
        Some(state) => match state {
            Ds::Creating | Ds::PendingBuild | Ds::BuildingSnapshot | Ds::PullingSnapshot => {
                SandboxState::Creating
            }
            Ds::Restoring | Ds::Starting => SandboxState::Starting,
            Ds::Started => SandboxState::Running,
            Ds::Stopping => SandboxState::Stopping,
            Ds::Stopped => SandboxState::Stopped,
            Ds::Archiving => SandboxState::Archiving,
            Ds::Archived => SandboxState::Archived,
            Ds::Resizing => SandboxState::Resizing,
            Ds::Snapshotting => SandboxState::Snapshotting,
            Ds::Forking => SandboxState::Forking,
            Ds::Pausing => SandboxState::Pausing,
            Ds::Paused => SandboxState::Paused,
            Ds::Resuming => SandboxState::Resuming,
            Ds::Destroying => SandboxState::Deleting,
            Ds::Destroyed => SandboxState::Deleted,
            Ds::Error | Ds::BuildFailed => SandboxState::Error,
            Ds::Unknown | Ds::UnknownDefaultOpenApi => SandboxState::Unknown,
        },
    }
}

fn status_from_sdk(sdk: &daytona_sdk::Sandbox) -> Result<SandboxStatus> {
    let id = SandboxId::try_new(&sdk.id)
        .map_err(|error| Error::invalid_spec("sandbox_id", error.to_string()))?;
    let mut status = SandboxStatus::new(id, map_state(sdk.state));
    status.provider_state = sdk.state.map(|state| state.to_string()).unwrap_or_default();
    status.error_reason.clone_from(&sdk.error_reason);
    status.labels = sdk
        .labels
        .iter()
        .filter(|(key, _)| *key != MANAGED_LABEL)
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    status.source.clone_from(&sdk.snapshot);
    let mut resources = Resources::default();
    resources.cpu_cores = to_u64(sdk.cpu)
        .and_then(|cpu| u32::try_from(cpu).ok())
        .filter(|cpu| *cpu > 0);
    resources.memory_mb = to_u64(sdk.memory * 1024.0).filter(|mb| *mb > 0);
    resources.disk_mb = to_u64(sdk.disk * 1024.0).filter(|mb| *mb > 0);
    status.resources = Some(resources);
    Ok(status)
}

/// Converts a non-negative float to `u64`, `None` when out of range.
#[expect(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "guarded by the range check"
)]
fn to_u64(value: f64) -> Option<u64> {
    (value.is_finite() && value >= 0.0 && value < u64::MAX as f64).then(|| value.round() as u64)
}

fn minutes(duration: Duration) -> i32 {
    i32::try_from(duration.as_secs() / 60)
        .unwrap_or(i32::MAX)
        .max(1)
}

fn gigabytes(mb: u64) -> i32 {
    i32::try_from(mb.div_ceil(1024)).unwrap_or(i32::MAX).max(1)
}

/// The Daytona provider.
pub struct DaytonaProvider {
    kind:         ProviderKind,
    capabilities: Capabilities,
    client:       DaytonaClient,
    snapshots:    DaytonaSnapshots,
    volumes:      DaytonaVolumes,
}

impl DaytonaProvider {
    /// Connects using the SDK's environment configuration.
    pub async fn connect() -> Result<Self> {
        let client = Client::new()
            .await
            .map_err(|error| daytona_error("connecting to daytona", &error))?;
        let client = Arc::new(client);
        Ok(Self {
            kind: ProviderKind::try_new("daytona").expect("static kind is valid"),
            capabilities: daytona_capabilities(),
            snapshots: DaytonaSnapshots {
                client: Arc::clone(&client),
            },
            volumes: DaytonaVolumes {
                client: Arc::clone(&client),
            },
            client,
        })
    }

    async fn handle(
        &self,
        sdk: daytona_sdk::Sandbox,
        events: Option<EventCallback>,
    ) -> Result<Arc<DaytonaSandbox>> {
        let working_dir = match sdk.get_working_dir().await {
            Ok(dir) => dir,
            // A stopped sandbox has no reachable toolbox; use the
            // conventional home until the next exec resolves it.
            Err(_) => FALLBACK_WORKING_DIR.to_owned(),
        };
        let id = SandboxId::try_new(&sdk.id)
            .map_err(|error| Error::invalid_spec("sandbox_id", error.to_string()))?;
        Ok(Arc::new(DaytonaSandbox {
            exec: DaytonaExec::new(
                Arc::clone(&self.client),
                sdk.id.clone(),
                working_dir.clone(),
            ),
            fs: DaytonaFs::new(
                Arc::clone(&self.client),
                sdk.id.clone(),
                working_dir.clone(),
            ),
            access: DaytonaAccess::new(Arc::clone(&self.client), sdk.id.clone()),
            id,
            capabilities: self.capabilities.clone(),
            client: Arc::clone(&self.client),
            sdk_id: sdk.id,
            working_dir,
            dispatcher: events.map(EventDispatcher::new),
        }))
    }
}

fn daytona_capabilities() -> Capabilities {
    let mut caps = Capabilities::minimal(Isolation::Vm);
    caps.lifecycle.archive = true;
    caps.lifecycle.resize = true;
    caps.lifecycle.recover = true;
    caps.lifecycle.refresh_activity = true;
    caps.lifecycle.timers = true;
    caps.lifecycle.labels = true;
    caps.fs.native = true;
    caps.fs.upload = true;
    caps.fs.download = true;
    caps.fs.permissions = true;
    caps.access.preview_urls = true;
    caps.access.signed_preview_urls = true;
    caps.access.ssh = true;
    caps.network.allow_all = true;
    caps.network.block_all = true;
    caps.network.cidr_allow_list = true;
    caps.snapshots = Some({
        let mut snapshots = SnapshotCaps::default();
        snapshots.from_image = true;
        snapshots.from_dockerfile = true;
        snapshots
    });
    caps.volumes = Some({
        let mut volumes = VolumeCaps::default();
        volumes.create_time_attach = true;
        volumes
    });
    caps
}

fn base_params(spec: &SandboxSpec) -> Result<SandboxBaseParams> {
    if spec.timers.ttl.is_some() {
        return Err(Error::invalid_spec(
            "timers",
            "daytona does not support a wall-clock ttl",
        ));
    }
    if spec.timers.auto_pause_after_idle.is_some() {
        return Err(Error::invalid_spec(
            "timers",
            "auto_pause is not supported by this provider version",
        ));
    }
    let (network_block_all, network_allow_list) = match &spec.network {
        NetworkPolicy::ProviderDefault => (None, None),
        NetworkPolicy::AllowAll => (Some(false), None),
        NetworkPolicy::Block => (Some(true), None),
        NetworkPolicy::CidrAllowList { cidrs } => (None, Some(cidrs.clone())),
        NetworkPolicy::DomainAllowList { .. } => {
            return Err(Error::invalid_spec(
                "network",
                "domain allow lists are not exposed by the daytona provider yet",
            ));
        }
        _ => return Err(Error::invalid_spec("network", "unsupported network policy")),
    };
    let mut labels: HashMap<String, String> = spec
        .labels
        .iter()
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    labels.insert(MANAGED_LABEL.to_owned(), "true".to_owned());
    Ok(SandboxBaseParams {
        name: spec.name.clone(),
        user: spec.user.clone(),
        language: None,
        env_vars: Some(
            spec.env
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
        ),
        labels: Some(labels),
        public: spec.public,
        auto_stop_interval: spec.timers.auto_stop_after_idle.map(minutes),
        auto_archive_interval: spec.timers.auto_archive_after_stop.map(minutes),
        auto_delete_interval: spec
            .timers
            .auto_delete_after_stop
            .map(minutes)
            .or(if spec.ephemeral { Some(0) } else { None }),
        volumes: (!spec.volumes.is_empty()).then(|| {
            spec.volumes
                .iter()
                .map(|mount| daytona_sdk::VolumeMount {
                    volume_id:  mount.volume.clone(),
                    mount_path: mount.mount_path.clone(),
                    subpath:    mount.subpath.clone(),
                })
                .collect()
        }),
        network_block_all,
        network_allow_list,
        ephemeral: spec.ephemeral.then_some(true),
    })
}

fn sdk_resources(resources: &Resources) -> Option<daytona_sdk::Resources> {
    if *resources == Resources::default() {
        return None;
    }
    Some(daytona_sdk::Resources {
        cpu:    resources
            .cpu_cores
            .and_then(|cores| i32::try_from(cores).ok()),
        gpu:    resources.gpus.and_then(|gpus| i32::try_from(gpus).ok()),
        memory: resources.memory_mb.map(gigabytes),
        disk:   resources.disk_mb.map(gigabytes),
    })
}

#[async_trait]
impl SandboxProvider for DaytonaProvider {
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
        let base = base_params(spec)?;
        let params = match &spec.source {
            SandboxSource::Image { reference } => CreateParams::Image(ImageParams {
                base,
                image: ImageSource::Name(reference.clone()),
                resources: sdk_resources(&spec.resources),
            }),
            SandboxSource::Dockerfile { content } => CreateParams::Image(ImageParams {
                base,
                image: ImageSource::Custom(DockerImage::from_dockerfile(content)),
                resources: sdk_resources(&spec.resources),
            }),
            SandboxSource::Snapshot { name } => CreateParams::Snapshot(SnapshotParams {
                base,
                snapshot: name.clone(),
            }),
            SandboxSource::HostDirectory => {
                return Err(Error::invalid_spec(
                    "source",
                    "the daytona provider needs an image, dockerfile, or snapshot source",
                ));
            }
            _ => return Err(Error::invalid_spec("source", "unsupported sandbox source")),
        };

        let dispatcher = events.map(EventDispatcher::new);
        if let Some(dispatcher) = &dispatcher {
            dispatcher
                .emit(SandboxEvent::ActionStarted {
                    action: LifecycleAction::Create,
                })
                .await;
        }
        let started = Instant::now();
        let options = CreateSandboxOptions {
            timeout:        Some(CREATE_TIMEOUT),
            wait_for_start: true,
            log_sender:     None,
        };
        let created = match self.client.create(params, options).await {
            Ok(created) => created,
            Err(error) => {
                let mapped = daytona_error("creating sandbox", &error);
                if let Some(dispatcher) = &dispatcher {
                    dispatcher
                        .emit(SandboxEvent::ActionFailed {
                            action: LifecycleAction::Create,
                            error:  ErrorReport::from(&mapped),
                        })
                        .await;
                }
                return Err(mapped);
            }
        };
        let handle = self.handle(created, None).await?;
        if let Some(dispatcher) = dispatcher {
            dispatcher
                .emit(SandboxEvent::ActionCompleted {
                    action:   LifecycleAction::Create,
                    duration: started.elapsed(),
                })
                .await;
            let handle = Arc::into_inner(handle)
                .map(|mut sandbox| {
                    sandbox.dispatcher = Some(dispatcher);
                    Arc::new(sandbox)
                })
                .expect("handle has a single owner at creation");
            return Ok(handle);
        }
        Ok(handle)
    }

    async fn attach(
        &self,
        id: &SandboxId,
        events: Option<EventCallback>,
    ) -> Result<Arc<dyn Sandbox>> {
        let sdk = match self.client.get(id.as_str()).await {
            Ok(sdk) => sdk,
            Err(error) if is_not_found(&error) => {
                return Err(Error::NotFound {
                    resource: ResourceKind::Sandbox,
                    id:       id.as_str().to_owned(),
                });
            }
            Err(error) => return Err(daytona_error("fetching sandbox", &error)),
        };
        if sdk.labels.get(MANAGED_LABEL).map(String::as_str) != Some("true") {
            return Err(Error::NotFound {
                resource: ResourceKind::Sandbox,
                id:       id.as_str().to_owned(),
            });
        }
        Ok(self.handle(sdk, events).await?)
    }

    async fn list(&self, filter: &SandboxFilter) -> Result<Vec<SandboxStatus>> {
        let mut labels: HashMap<String, String> = filter
            .labels
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect();
        labels.insert(MANAGED_LABEL.to_owned(), "true".to_owned());
        let page = self
            .client
            .list(Some(&labels), None, None)
            .await
            .map_err(|error| daytona_error("listing sandboxes", &error))?;
        page.items.iter().map(status_from_sdk).collect()
    }

    fn snapshots(&self) -> Option<&dyn SnapshotService> {
        Some(&self.snapshots)
    }

    fn volumes(&self) -> Option<&dyn VolumeService> {
        Some(&self.volumes)
    }
}

/// A Daytona-backed sandbox handle.
pub struct DaytonaSandbox {
    id:           SandboxId,
    capabilities: Capabilities,
    client:       DaytonaClient,
    sdk_id:       String,
    working_dir:  String,
    exec:         DaytonaExec,
    fs:           DaytonaFs,
    access:       DaytonaAccess,
    dispatcher:   Option<EventDispatcher>,
}

impl DaytonaSandbox {
    async fn sdk(&self) -> Result<daytona_sdk::Sandbox> {
        self.client
            .get(&self.sdk_id)
            .await
            .map_err(|error| daytona_error("fetching sandbox", &error))
    }

    async fn emit_action(&self, action: LifecycleAction, outcome: &Result<()>) {
        let Some(dispatcher) = &self.dispatcher else {
            return;
        };
        match outcome {
            Ok(()) => {
                dispatcher
                    .emit(SandboxEvent::ActionCompleted {
                        action,
                        duration: Duration::ZERO,
                    })
                    .await;
            }
            Err(error) => {
                dispatcher
                    .emit(SandboxEvent::ActionFailed {
                        action,
                        error: ErrorReport::from(error),
                    })
                    .await;
            }
        }
    }
}

#[async_trait]
impl Sandbox for DaytonaSandbox {
    fn id(&self) -> &SandboxId {
        &self.id
    }

    fn capabilities(&self) -> &Capabilities {
        &self.capabilities
    }

    async fn describe(&self) -> Result<SandboxStatus> {
        match self.client.get(&self.sdk_id).await {
            Ok(sdk) => status_from_sdk(&sdk),
            Err(error) if is_not_found(&error) => {
                Ok(SandboxStatus::new(self.id.clone(), SandboxState::Deleted))
            }
            Err(error) => Err(daytona_error("fetching sandbox", &error)),
        }
    }

    fn working_directory(&self) -> &str {
        &self.working_dir
    }

    async fn platform_info(&self) -> Result<PlatformInfo> {
        let result = self
            .exec
            .run(&ExecSpec::new("uname -s -m -r").timeout(Duration::from_secs(60)))
            .await?;
        let text = result.stdout_lossy();
        let mut parts = text.split_whitespace();
        let os = parts.next().unwrap_or("linux").to_lowercase();
        let arch = parts.next().unwrap_or("").to_owned();
        let version = parts.next().unwrap_or("").to_owned();
        Ok(PlatformInfo::new(os, arch, version))
    }

    async fn start(&self) -> Result<()> {
        let outcome = self
            .client
            .start(&self.sdk_id)
            .await
            .map(|_| ())
            .map_err(|error| daytona_error("starting sandbox", &error));
        self.emit_action(LifecycleAction::Start, &outcome).await;
        outcome
    }

    async fn stop(&self) -> Result<()> {
        let outcome = match self.client.stop(&self.sdk_id).await {
            Ok(_) => Ok(()),
            // Ephemeral sandboxes destroy themselves on stop.
            Err(error) if is_not_found(&error) => Ok(()),
            Err(error) => Err(daytona_error("stopping sandbox", &error)),
        };
        self.emit_action(LifecycleAction::Stop, &outcome).await;
        outcome
    }

    async fn delete(&self) -> Result<()> {
        let outcome = match self.client.delete(&self.sdk_id).await {
            Ok(()) => Ok(()),
            Err(error) if is_not_found(&error) => Ok(()),
            Err(error) => Err(daytona_error("deleting sandbox", &error)),
        };
        self.emit_action(LifecycleAction::Delete, &outcome).await;
        outcome
    }

    async fn archive(&self) -> Result<()> {
        let outcome = async {
            let mut sdk = self.sdk().await?;
            sdk.archive()
                .await
                .map_err(|error| daytona_error("archiving sandbox", &error))
        }
        .await;
        self.emit_action(LifecycleAction::Archive, &outcome).await;
        outcome
    }

    async fn recover(&self) -> Result<()> {
        let mut sdk = self.sdk().await?;
        sdk.recover()
            .await
            .map_err(|error| daytona_error("recovering sandbox", &error))
    }

    async fn refresh_activity(&self) -> Result<()> {
        let sdk = self.sdk().await?;
        sdk.refresh_activity()
            .await
            .map_err(|error| daytona_error("refreshing activity", &error))
    }

    async fn resize(&self, resources: &Resources) -> Result<()> {
        let Some(sdk_resources) = sdk_resources(resources) else {
            return Err(Error::invalid_spec(
                "resources",
                "resize needs at least one resource",
            ));
        };
        let outcome = async {
            let mut sdk = self.sdk().await?;
            sdk.resize(&sdk_resources)
                .await
                .map_err(|error| daytona_error("resizing sandbox", &error))
        }
        .await;
        self.emit_action(LifecycleAction::Resize, &outcome).await;
        outcome
    }

    async fn set_timers(&self, timers: &LifecycleTimers) -> Result<()> {
        if timers.ttl.is_some() || timers.auto_pause_after_idle.is_some() {
            return Err(Error::invalid_spec(
                "timers",
                "ttl and auto_pause are not supported by this provider version",
            ));
        }
        let mut sdk = self.sdk().await?;
        if let Some(idle) = timers.auto_stop_after_idle {
            sdk.set_autostop_interval(minutes(idle))
                .await
                .map_err(|error| daytona_error("setting auto-stop", &error))?;
        }
        if let Some(archive) = timers.auto_archive_after_stop {
            sdk.set_auto_archive_interval(minutes(archive))
                .await
                .map_err(|error| daytona_error("setting auto-archive", &error))?;
        }
        if let Some(delete) = timers.auto_delete_after_stop {
            sdk.set_auto_delete_interval(minutes(delete))
                .await
                .map_err(|error| daytona_error("setting auto-delete", &error))?;
        }
        Ok(())
    }

    async fn set_labels(&self, labels: &BTreeMap<String, String>) -> Result<()> {
        let mut all: HashMap<String, String> = labels
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect();
        all.insert(MANAGED_LABEL.to_owned(), "true".to_owned());
        let mut sdk = self.sdk().await?;
        sdk.set_labels(all)
            .await
            .map(|_| ())
            .map_err(|error| daytona_error("setting labels", &error))
    }

    fn exec(&self) -> &dyn Exec {
        &self.exec
    }

    fn fs(&self) -> &dyn Filesystem {
        &self.fs
    }

    fn preview_urls(&self) -> Option<&dyn PreviewUrls> {
        Some(&self.access)
    }

    fn ssh(&self) -> Option<&dyn SshAccess> {
        Some(&self.access)
    }
}

fn map_snapshot_state(state: ApiSnapshotState) -> SnapshotState {
    use ApiSnapshotState as Ds;
    match state {
        Ds::Building | Ds::Pending | Ds::Pulling | Ds::Snapshotting => SnapshotState::Building,
        Ds::Active => SnapshotState::Active,
        Ds::Inactive => SnapshotState::Inactive,
        Ds::Error | Ds::BuildFailed => SnapshotState::Error,
        Ds::Removing => SnapshotState::Deleting,
        Ds::UnknownDefaultOpenApi => SnapshotState::Unknown,
    }
}

struct DaytonaSnapshots {
    client: DaytonaClient,
}

#[async_trait]
impl SnapshotService for DaytonaSnapshots {
    async fn create(&self, spec: &SnapshotSpec) -> Result<SnapshotId> {
        let image = match &spec.source {
            SnapshotSource::Image { reference } => ImageSource::Name(reference.clone()),
            SnapshotSource::Dockerfile { content } => {
                ImageSource::Custom(DockerImage::from_dockerfile(content))
            }
            SnapshotSource::Sandbox { .. } => {
                return Err(Error::invalid_spec(
                    "source",
                    "snapshots from a live sandbox are not supported by this provider version",
                ));
            }
            _ => return Err(Error::invalid_spec("source", "unsupported snapshot source")),
        };
        let name = spec.name.clone().unwrap_or_else(|| {
            format!(
                "sandbox-driver-{}",
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_or(0, |elapsed| elapsed.as_secs())
            )
        });
        let params = CreateSnapshotParams {
            name,
            image,
            resources: sdk_resources(&spec.resources),
            entrypoint: None,
        };
        let created = self
            .client
            .snapshot
            .create(&params)
            .await
            .map_err(|error| daytona_error("creating snapshot", &error))?;
        SnapshotId::try_new(created.id)
            .map_err(|error| Error::invalid_spec("snapshot_id", error.to_string()))
    }

    async fn get(&self, id: &SnapshotId) -> Result<SnapshotStatus> {
        let dto = self
            .client
            .snapshot
            .get(id.as_str())
            .await
            .map_err(|error| {
                if is_not_found(&error) {
                    Error::NotFound {
                        resource: ResourceKind::Snapshot,
                        id:       id.as_str().to_owned(),
                    }
                } else {
                    daytona_error("fetching snapshot", &error)
                }
            })?;
        let mut status = SnapshotStatus::new(id.clone(), map_snapshot_state(dto.state));
        status.name = Some(dto.name);
        status.error_reason.clone_from(&dto.error_reason);
        Ok(status)
    }

    async fn list(&self, filter: &SnapshotFilter) -> Result<Vec<SnapshotStatus>> {
        let page = self
            .client
            .snapshot
            .list(None, None)
            .await
            .map_err(|error| daytona_error("listing snapshots", &error))?;
        let mut statuses = Vec::new();
        for dto in page.items {
            if let Some(name) = &filter.name {
                if dto.name != *name {
                    continue;
                }
            }
            let id = SnapshotId::try_new(dto.id)
                .map_err(|error| Error::invalid_spec("snapshot_id", error.to_string()))?;
            let mut status = SnapshotStatus::new(id, map_snapshot_state(dto.state));
            status.name = Some(dto.name);
            status.error_reason.clone_from(&dto.error_reason);
            statuses.push(status);
        }
        Ok(statuses)
    }

    async fn delete(&self, id: &SnapshotId) -> Result<()> {
        match self.client.snapshot.delete(id.as_str()).await {
            Ok(()) => Ok(()),
            Err(error) if is_not_found(&error) => Ok(()),
            Err(error) => Err(daytona_error("deleting snapshot", &error)),
        }
    }
}

fn map_volume_state(state: ApiVolumeState) -> VolumeState {
    use ApiVolumeState as Ds;
    match state {
        Ds::Creating | Ds::PendingCreate => VolumeState::Creating,
        Ds::Ready => VolumeState::Ready,
        Ds::Deleting | Ds::PendingDelete => VolumeState::Deleting,
        Ds::Deleted => VolumeState::Deleted,
        Ds::Error => VolumeState::Error,
        Ds::UnknownDefaultOpenApi => VolumeState::Unknown,
    }
}

fn volume_status(dto: VolumeDto) -> Result<VolumeStatus> {
    let id = VolumeId::try_new(dto.id)
        .map_err(|error| Error::invalid_spec("volume_id", error.to_string()))?;
    let mut status = VolumeStatus::new(id, map_volume_state(dto.state));
    status.name = Some(dto.name);
    status.error_reason = dto.error_reason;
    Ok(status)
}

struct DaytonaVolumes {
    client: DaytonaClient,
}

#[async_trait]
impl VolumeService for DaytonaVolumes {
    async fn create(&self, spec: &VolumeSpec) -> Result<VolumeId> {
        // Daytona volumes are elastic; a requested size is ignored.
        let dto = self
            .client
            .volume
            .create(&spec.name)
            .await
            .map_err(|error| daytona_error("creating volume", &error))?;
        VolumeId::try_new(dto.id)
            .map_err(|error| Error::invalid_spec("volume_id", error.to_string()))
    }

    async fn get(&self, id: &VolumeId) -> Result<VolumeStatus> {
        let dto = self.client.volume.get(id.as_str()).await.map_err(|error| {
            if is_not_found(&error) {
                Error::NotFound {
                    resource: ResourceKind::Volume,
                    id:       id.as_str().to_owned(),
                }
            } else {
                daytona_error("fetching volume", &error)
            }
        })?;
        volume_status(dto)
    }

    async fn list(&self) -> Result<Vec<VolumeStatus>> {
        let volumes = self
            .client
            .volume
            .list()
            .await
            .map_err(|error| daytona_error("listing volumes", &error))?;
        volumes.into_iter().map(volume_status).collect()
    }

    async fn delete(&self, id: &VolumeId) -> Result<()> {
        match self.client.volume.delete(id.as_str()).await {
            Ok(()) => Ok(()),
            Err(error) if is_not_found(&error) => Ok(()),
            Err(error) => Err(daytona_error("deleting volume", &error)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minutes_round_up_to_at_least_one() {
        assert_eq!(minutes(Duration::from_secs(30)), 1);
        assert_eq!(minutes(Duration::from_secs(120)), 2);
    }

    #[test]
    fn gigabytes_round_up() {
        assert_eq!(gigabytes(1), 1);
        assert_eq!(gigabytes(1024), 1);
        assert_eq!(gigabytes(1025), 2);
    }
}
