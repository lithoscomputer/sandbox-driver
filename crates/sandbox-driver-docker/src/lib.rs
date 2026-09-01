//! Docker container sandbox provider.
//!
//! Containers created from OCI images, with kernel-sharing container
//! isolation (`Isolation::Container`). The Docker socket is
//! host-root-equivalent, so this provider is host-trusted by definition.
//!
//! The container's data plane is hybrid: file content moves through
//! the daemon's archive API (single-call transfers of any size, reads
//! that work on stopped containers), while metadata operations stay
//! exec-derived — so `Capabilities::fs` still reports `native: false`.
//! Every image must provide `/bin/bash` (the
//! Bash contract) and a Linux userland with `stat`, `find`, `base64`,
//! and `setsid` (kill semantics need a separate session; an image
//! without it fails every exec with a clear message). Because Docker advertises
//! the normalized Git and background-services facets, the image must also
//! provide `git` and the service commands documented by
//! [`sandbox_driver::Services`] on `PATH`.
//!
//! # Runtime behavior
//!
//! Async on Tokio; the caller owns the runtime. Spawned tasks: stream
//! demux and stdin writers scoped to a running exec, and kill requests
//! on cancellation that run from `/` and fail loudly when the stop
//! cannot be requested. Docker itself is the
//! sandbox registry — handles re-attach by container id across process
//! restarts.

mod access;
mod exec;
mod fs;
mod pty;

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bollard::Docker;
use bollard::container::{
    Config, CreateContainerOptions, InspectContainerOptions, ListContainersOptions,
    RemoveContainerOptions, StartContainerOptions, StopContainerOptions,
};
use bollard::image::CreateImageOptions;
use bollard::models::{ContainerInspectResponse, ContainerStateStatusEnum, HostConfig};
use futures_util::StreamExt;
use sandbox_driver::{
    Action, Capabilities, Error, EventContext, EventEmitter, EventSubject, Exec, ExecSpec,
    Filesystem, HealthStatus, Isolation, LifecycleTimers, NetworkPolicy, OperationReporter,
    PlatformInfo, Progress, ProgressCode, ProviderError, ProviderHealth, ProviderKind, Pty,
    PtyCaps, ResourceKind, Result, Sandbox, SandboxFilter, SandboxId, SandboxKind, SandboxProvider,
    SandboxSource, SandboxSpec, SandboxState, SandboxStatus, ShellCommand,
};

use crate::access::DockerShellCommand;
pub use crate::exec::DockerExec;
use crate::exec::{
    BASH_ENV_VAR, docker_error, is_conflict, is_not_found, is_not_modified, shell_quote,
    tolerate_not_modified,
};
use crate::fs::DockerFs;
use crate::pty::DockerPty;

const MANAGED_LABEL: &str = "sh.sandbox-driver.managed";
const DEFAULT_WORKING_DIRECTORY: &str = "/workspace";
const RUNTIME_DIRECTORY_PARENT: &str = "/tmp/sandbox-driver";
const RUNTIME_DIRECTORY: &str = "/tmp/sandbox-driver/runtime";

/// Options the Docker provider reads from `SandboxSpec::provider_config`.
///
/// Schema: `{"auto_pull": bool}` — whether a missing image may be pulled
/// during create (default `true`). Unknown fields are rejected so typos
/// fail loudly instead of silently using defaults.
struct DockerProviderConfig {
    auto_pull: bool,
}

fn provider_config(value: &serde_json::Value) -> Result<DockerProviderConfig> {
    let mut config = DockerProviderConfig { auto_pull: true };
    match value {
        serde_json::Value::Null => {}
        serde_json::Value::Object(fields) => {
            for (key, field) in fields {
                match key.as_str() {
                    "auto_pull" => {
                        config.auto_pull = field.as_bool().ok_or_else(|| {
                            Error::invalid_spec("provider_config.auto_pull", "expected a boolean")
                        })?;
                    }
                    other => {
                        return Err(Error::invalid_spec(
                            "provider_config",
                            format!("unknown field {other:?}"),
                        ));
                    }
                }
            }
        }
        _ => {
            return Err(Error::invalid_spec("provider_config", "expected an object"));
        }
    }
    Ok(config)
}

/// The Docker provider. One per process, sharing one daemon connection.
pub struct DockerProvider {
    kind:         ProviderKind,
    capabilities: Capabilities,
    docker:       Docker,
}

impl DockerProvider {
    /// Connects to the local Docker daemon and verifies it responds.
    #[tracing::instrument(skip_all, fields(provider_kind = "docker"), err)]
    pub async fn connect() -> Result<Self> {
        let docker = Docker::connect_with_local_defaults()
            .map_err(|error| docker_error("connecting to the docker daemon", error))?;
        docker
            .ping()
            .await
            .map_err(|error| docker_error("pinging the docker daemon", error))?;
        Ok(Self {
            kind: ProviderKind::try_new("docker").expect("static kind is valid"),
            capabilities: docker_capabilities(),
            docker,
        })
    }

    #[tracing::instrument(skip_all, fields(provider_kind = %self.kind), err)]
    async fn ensure_image(
        &self,
        reference: &str,
        auto_pull: bool,
        reporter: &OperationReporter,
    ) -> Result<()> {
        match self.docker.inspect_image(reference).await {
            Ok(_) => return Ok(()),
            // Only a definitive "not present" justifies a pull; a daemon
            // or transport failure must surface as what it is.
            Err(error) if is_not_found(&error) => {}
            Err(error) => return Err(docker_error("inspecting image", error)),
        }
        if !auto_pull {
            return Err(Error::Provider(ProviderError::new(
                self.kind.clone(),
                format!(
                    "image {reference} is not present locally and \
                     provider_config.auto_pull is false"
                ),
            )));
        }
        reporter
            .progress(
                Progress::new(ProgressCode::IMAGE_PULL)
                    .message(format!("pulling image {reference}")),
            )
            .await;
        let mut stream = self
            .docker
            .create_image(Some(pull_options(reference)), None, None);
        while let Some(progress) = stream.next().await {
            progress.map_err(|error| docker_error("pulling image", error))?;
        }
        Ok(())
    }

    #[tracing::instrument(
        skip_all,
        fields(provider_kind = %self.kind, sandbox_id = container_id),
        err
    )]
    async fn inspect(&self, container_id: &str) -> Result<ContainerInspectResponse> {
        self.docker
            .inspect_container(container_id, None::<InspectContainerOptions>)
            .await
            .map_err(|error| {
                if is_not_found(&error) {
                    Error::NotFound {
                        resource: ResourceKind::Sandbox,
                        id:       container_id.to_owned(),
                    }
                } else {
                    docker_error("inspecting container", error)
                }
            })
    }

    fn handle(
        &self,
        container_id: String,
        name: Option<String>,
        working_dir: String,
        labels: BTreeMap<String, String>,
        env: BTreeMap<String, String>,
        events: EventEmitter,
    ) -> Arc<DockerSandbox> {
        let pty = DockerPty::new(
            self.docker.clone(),
            container_id.clone(),
            working_dir.clone(),
        );
        let shell_command = DockerShellCommand::new(container_id.clone(), working_dir.clone());
        let exec = Arc::new(DockerExec::new(
            self.docker.clone(),
            container_id.clone(),
            working_dir.clone(),
            env,
        ));
        let fs = DockerFs::new(
            self.docker.clone(),
            container_id.clone(),
            working_dir.clone(),
            Arc::clone(&exec) as Arc<dyn Exec>,
        );
        Arc::new(DockerSandbox {
            id: SandboxId::try_new(container_id).expect("container id is a valid sandbox id"),
            name,
            capabilities: self.capabilities.clone(),
            docker: self.docker.clone(),
            working_dir,
            labels,
            exec,
            fs,
            pty,
            shell_command,
            events,
        })
    }
}

/// Splits an image reference for the pull API. An empty tag pulls every
/// tag of the repository, so bare references default to `latest`; digest
/// references pass through whole.
fn pull_options(reference: &str) -> CreateImageOptions<'static, String> {
    if reference.contains('@') {
        return CreateImageOptions {
            from_image: reference.to_owned(),
            ..Default::default()
        };
    }
    // A colon only marks a tag when the remainder has no `/` — otherwise
    // it is a registry port (`registry:5000/img`).
    let (repo, tag) = match reference.rsplit_once(':') {
        Some((repo, tag)) if !tag.contains('/') => (repo.to_owned(), tag.to_owned()),
        _ => (reference.to_owned(), "latest".to_owned()),
    };
    CreateImageOptions {
        from_image: repo,
        tag,
        ..Default::default()
    }
}

fn docker_capabilities() -> Capabilities {
    let mut caps = Capabilities::minimal(Isolation::Container);
    caps.lifecycle.pause = true;
    caps.exec.live_streaming = true;
    caps.exec.streams_separated = true;
    caps.exec.stdin = true;
    caps.exec.cancel = true;
    caps.exec.stdio_process = true;
    let mut pty = PtyCaps::default();
    pty.resize = true;
    caps.pty = Some(pty);
    caps.access.shell_command = true;
    caps.fs.native = false;
    caps.fs.upload = true;
    caps.fs.download = true;
    caps.fs.permissions = true;
    caps.git.supported = true;
    caps.services.supported = true;
    caps.network.allow_all = true;
    caps.network.block_all = true;
    caps
}

fn map_state(inspect: &ContainerInspectResponse) -> SandboxState {
    let Some(state) = &inspect.state else {
        return SandboxState::Unknown;
    };
    if state.paused == Some(true) {
        return SandboxState::Paused;
    }
    match state.status {
        Some(ContainerStateStatusEnum::RUNNING) => SandboxState::Running,
        Some(ContainerStateStatusEnum::CREATED | ContainerStateStatusEnum::EXITED) => {
            SandboxState::Stopped
        }
        Some(ContainerStateStatusEnum::PAUSED) => SandboxState::Paused,
        Some(ContainerStateStatusEnum::RESTARTING) => SandboxState::Starting,
        Some(ContainerStateStatusEnum::REMOVING) => SandboxState::Deleting,
        Some(ContainerStateStatusEnum::DEAD) => SandboxState::Error,
        Some(ContainerStateStatusEnum::EMPTY) | None => SandboxState::Unknown,
    }
}

fn status_from_inspect(id: SandboxId, inspect: &ContainerInspectResponse) -> SandboxStatus {
    let mut status = SandboxStatus::new(id, map_state(inspect));
    status.name = normalized_container_name(inspect.name.as_deref());
    status.sandbox_kind = Some(SandboxKind::Container);
    status.provider_state = inspect
        .state
        .as_ref()
        .and_then(|state| state.status)
        .map(|state| state.to_string())
        .unwrap_or_default();
    if let Some(config) = &inspect.config {
        if let Some(labels) = &config.labels {
            status.labels = labels
                .iter()
                .filter(|(key, _)| *key != MANAGED_LABEL)
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect();
        }
        status.source.clone_from(&config.image);
    }
    status
}

fn normalized_container_name(name: Option<&str>) -> Option<String> {
    name.map(|name| name.trim_start_matches('/'))
        .filter(|name| !name.is_empty())
        .map(str::to_owned)
}

fn network_mode(policy: &NetworkPolicy) -> Result<Option<String>> {
    match policy {
        NetworkPolicy::ProviderDefault => Ok(None),
        NetworkPolicy::AllowAll => Ok(Some("bridge".to_owned())),
        NetworkPolicy::Block => Ok(Some("none".to_owned())),
        NetworkPolicy::CidrAllowList { .. } => Err(Error::invalid_spec(
            "network",
            "the docker provider does not support CIDR allow lists",
        )),
        NetworkPolicy::DomainAllowList { .. } => Err(Error::invalid_spec(
            "network",
            "the docker provider does not support domain allow lists",
        )),
        _ => Err(Error::invalid_spec("network", "unsupported network policy")),
    }
}

fn validate_supported_creation_fields(spec: &SandboxSpec) -> Result<()> {
    if spec.resources.disk_mb.is_some() {
        return Err(Error::invalid_spec(
            "resources.disk_mb",
            "the docker provider does not enforce a writable-layer disk limit",
        ));
    }
    if spec.resources.gpus.is_some() {
        return Err(Error::invalid_spec(
            "resources.gpus",
            "the docker provider does not configure GPU devices",
        ));
    }
    if spec.user.is_some() {
        return Err(Error::invalid_spec(
            "user",
            "the docker provider does not configure the container user",
        ));
    }
    if spec.timers != LifecycleTimers::default() {
        return Err(Error::invalid_spec(
            "timers",
            "the docker provider does not support lifecycle timers",
        ));
    }
    if spec.ephemeral {
        return Err(Error::invalid_spec(
            "ephemeral",
            "the docker provider does not delete a container when it stops",
        ));
    }
    if spec.public.is_some() {
        return Err(Error::invalid_spec(
            "public",
            "the docker provider does not manage public access",
        ));
    }
    if spec.region.is_some() {
        return Err(Error::invalid_spec(
            "region",
            "the docker provider does not select a region",
        ));
    }
    Ok(())
}

#[async_trait]
impl SandboxProvider for DockerProvider {
    fn kind(&self) -> &ProviderKind {
        &self.kind
    }

    fn capabilities(&self) -> &Capabilities {
        &self.capabilities
    }

    #[tracing::instrument(skip_all, fields(provider_kind = %self.kind), err)]
    async fn create(
        &self,
        spec: &SandboxSpec,
        events: Option<EventContext>,
    ) -> Result<Arc<dyn Sandbox>> {
        spec.validate()?;
        validate_supported_creation_fields(spec)?;
        if matches!(spec.sandbox_kind, Some(kind) if kind != SandboxKind::Container) {
            return Err(Error::invalid_spec(
                "sandbox_kind",
                "the docker provider creates container sandboxes only",
            ));
        }
        let SandboxSource::Image { reference } = &spec.source else {
            return Err(Error::invalid_spec(
                "source",
                "the docker provider supports SandboxSource::Image only",
            ));
        };
        if !spec.volumes.is_empty() {
            return Err(Error::invalid_spec(
                "volumes",
                "the docker provider does not support volumes yet",
            ));
        }
        let config_options = provider_config(&spec.provider_config)?;
        let network = network_mode(&spec.network)?;

        let emitter = EventEmitter::new(self.kind.clone(), events);
        let handle_emitter = emitter.clone();
        emitter
            .run(
                EventSubject::pending_sandbox(spec.name.clone()),
                Action::Create,
                |reporter| async move {
                    self.ensure_image(reference, config_options.auto_pull, &reporter)
                        .await?;

                    let working_dir = spec
                        .working_directory
                        .clone()
                        .unwrap_or_else(|| DEFAULT_WORKING_DIRECTORY.to_owned());
                    let mut labels: HashMap<String, String> = spec
                        .labels
                        .iter()
                        .map(|(key, value)| (key.clone(), value.clone()))
                        .collect();
                    labels.insert(MANAGED_LABEL.to_owned(), "true".to_owned());

                    let host_config = HostConfig {
                        network_mode: network,
                        memory: spec
                            .resources
                            .memory_mb
                            .and_then(|mb| i64::try_from(mb).ok())
                            .map(|mb| mb * 1024 * 1024),
                        cpu_quota: spec
                            .resources
                            .cpu_cores
                            .map(|cores| i64::from(cores) * 100_000),
                        ..Default::default()
                    };
                    // Blank BASH_ENV at the container level too: an image (or spec)
                    // startup file would otherwise run inside the init command below
                    // and can kill the container the moment it starts.
                    let mut env_entries: Vec<String> = spec
                        .env
                        .iter()
                        .filter(|(key, _)| key.as_str() != BASH_ENV_VAR)
                        .map(|(key, value)| format!("{key}={value}"))
                        .collect();
                    env_entries.push(format!("{BASH_ENV_VAR}="));
                    let config = Config {
                        image: Some(reference.clone()),
                        cmd: Some(vec![
                            "/bin/bash".to_owned(),
                            "-c".to_owned(),
                            format!(
                                "mkdir -p {working_dir} {runtime_dir} && chmod 0700 \
                                 {runtime_parent} {runtime_dir} && exec sleep infinity",
                                working_dir = shell_quote(&working_dir),
                                runtime_parent = shell_quote(RUNTIME_DIRECTORY_PARENT),
                                runtime_dir = shell_quote(RUNTIME_DIRECTORY),
                            ),
                        ]),
                        working_dir: Some(working_dir.clone()),
                        env: Some(env_entries),
                        labels: Some(labels),
                        host_config: Some(host_config),
                        ..Default::default()
                    };
                    let options = spec.name.clone().map(|name| CreateContainerOptions {
                        name,
                        platform: None,
                    });
                    let created = self
                        .docker
                        .create_container(options, config)
                        .await
                        .map_err(|error| {
                            // A name collision is a caller-actionable branch, not
                            // an opaque daemon failure.
                            if is_conflict(&error) && spec.name.is_some() {
                                Error::invalid_spec(
                                    "name",
                                    "a container with this name already exists",
                                )
                            } else {
                                docker_error("creating container", error)
                            }
                        })?;
                    let event_id = SandboxId::try_new(created.id.clone())
                        .map_err(|error| Error::invalid_spec("sandbox_id", error.to_string()))?;
                    reporter.set_subject(EventSubject::sandbox(Some(event_id)));
                    self.docker
                        .start_container(&created.id, None::<StartContainerOptions<String>>)
                        .await
                        .map_err(|error| docker_error("starting container", error))?;
                    Ok(self.handle(
                        created.id,
                        spec.name.clone(),
                        working_dir,
                        spec.labels.clone(),
                        spec.env.clone(),
                        handle_emitter,
                    ) as Arc<dyn Sandbox>)
                },
            )
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
                    let inspect = self.inspect(id.as_str()).await?;
                    let config = inspect.config.as_ref();
                    let labels = config.and_then(|config| config.labels.as_ref());
                    if labels
                        .and_then(|labels| labels.get(MANAGED_LABEL))
                        .map(String::as_str)
                        != Some("true")
                    {
                        return Err(Error::NotFound {
                            resource: ResourceKind::Sandbox,
                            id:       id.as_str().to_owned(),
                        });
                    }
                    let working_dir = config
                        .and_then(|config| config.working_dir.clone())
                        .unwrap_or_else(|| DEFAULT_WORKING_DIRECTORY.to_owned());
                    let user_labels: BTreeMap<String, String> = labels
                        .map(|labels| {
                            labels
                                .iter()
                                .filter(|(key, _)| *key != MANAGED_LABEL)
                                .map(|(key, value)| (key.clone(), value.clone()))
                                .collect()
                        })
                        .unwrap_or_default();
                    Ok(self.handle(
                        inspect.id.clone().unwrap_or_else(|| id.as_str().to_owned()),
                        normalized_container_name(inspect.name.as_deref()),
                        working_dir,
                        user_labels,
                        BTreeMap::new(),
                        handle_emitter,
                    ) as Arc<dyn Sandbox>)
                },
            )
            .await
    }

    #[tracing::instrument(skip_all, fields(provider_kind = %self.kind), err)]
    async fn health(&self) -> Result<ProviderHealth> {
        match self.docker.ping().await {
            Ok(_) => Ok(ProviderHealth::new(HealthStatus::Ok)),
            Err(error) => {
                tracing::warn!("docker provider health check failed");
                let mut health = ProviderHealth::new(HealthStatus::Unreachable);
                health.message = Some(format!("pinging the docker daemon failed: {error}"));
                Ok(health)
            }
        }
    }

    #[tracing::instrument(
        skip_all,
        fields(provider_kind = %self.kind, label_count = filter.labels.len()),
        err
    )]
    async fn list(&self, filter: &SandboxFilter) -> Result<Vec<SandboxStatus>> {
        let mut label_filters = vec![format!("{MANAGED_LABEL}=true")];
        for (key, value) in &filter.labels {
            label_filters.push(format!("{key}={value}"));
        }
        let mut filters = HashMap::new();
        filters.insert("label".to_owned(), label_filters);
        let options = ListContainersOptions {
            all: true,
            filters,
            ..Default::default()
        };
        let containers = self
            .docker
            .list_containers(Some(options))
            .await
            .map_err(|error| docker_error("listing containers", error))?;
        let mut statuses = Vec::new();
        for container in containers {
            let Some(id) = container.id else { continue };
            // A container deleted between list and inspect is a benign
            // race; any other inspect failure must not silently shrink
            // the listing — a reconciler would treat the missing
            // sandbox as gone.
            let inspect = match self.inspect(&id).await {
                Ok(inspect) => inspect,
                Err(Error::NotFound { .. }) => continue,
                Err(error) => return Err(error),
            };
            let sandbox_id = SandboxId::try_new(id)
                .map_err(|error| Error::invalid_spec("id", error.to_string()))?;
            statuses.push(status_from_inspect(sandbox_id, &inspect));
        }
        Ok(statuses)
    }
}

/// A container-backed sandbox.
pub struct DockerSandbox {
    id:            SandboxId,
    name:          Option<String>,
    capabilities:  Capabilities,
    docker:        Docker,
    working_dir:   String,
    labels:        BTreeMap<String, String>,
    exec:          Arc<DockerExec>,
    fs:            DockerFs,
    pty:           DockerPty,
    shell_command: DockerShellCommand,
    events:        EventEmitter,
}

#[async_trait]
impl Sandbox for DockerSandbox {
    fn id(&self) -> &SandboxId {
        &self.id
    }

    fn capabilities(&self) -> &Capabilities {
        &self.capabilities
    }

    #[tracing::instrument(skip_all, fields(provider_kind = "docker", sandbox_id = %self.id), err)]
    async fn describe(&self) -> Result<SandboxStatus> {
        match self
            .docker
            .inspect_container(self.id.as_str(), None::<InspectContainerOptions>)
            .await
        {
            Ok(inspect) => {
                let mut status = status_from_inspect(self.id.clone(), &inspect);
                if status.labels.is_empty() {
                    status.labels = self.labels.clone();
                }
                Ok(status)
            }
            Err(error) if is_not_found(&error) => {
                let mut status = SandboxStatus::new(self.id.clone(), SandboxState::Deleted);
                status.name.clone_from(&self.name);
                status.sandbox_kind = Some(SandboxKind::Container);
                Ok(status)
            }
            Err(error) => Err(docker_error("inspecting container", error)),
        }
    }

    fn working_directory(&self) -> &str {
        &self.working_dir
    }

    fn runtime_directory(&self) -> Option<&str> {
        Some(RUNTIME_DIRECTORY)
    }

    #[tracing::instrument(skip_all, fields(provider_kind = "docker", sandbox_id = %self.id), err)]
    async fn platform_info(&self) -> Result<PlatformInfo> {
        // uname prints its fields in canonical order — sysname, release,
        // machine — regardless of flag order.
        let result = self
            .exec
            .run(&ExecSpec::new("uname -s -r -m").timeout(Duration::from_secs(30)))
            .await?;
        let text = result.stdout_lossy();
        let mut parts = text.split_whitespace();
        let os = parts.next().unwrap_or("linux").to_lowercase();
        let version = parts.next().unwrap_or("").to_owned();
        let arch = parts.next().unwrap_or("").to_owned();
        Ok(PlatformInfo::new(os, arch, version))
    }

    #[tracing::instrument(skip_all, fields(provider_kind = "docker", sandbox_id = %self.id), err)]
    async fn start(&self) -> Result<()> {
        self.events
            .run(
                EventSubject::sandbox(Some(self.id.clone())),
                Action::Start,
                |_| async {
                    let inspect = self
                        .docker
                        .inspect_container(self.id.as_str(), None::<InspectContainerOptions>)
                        .await
                        .map_err(|error| docker_error("inspecting container", error))?;
                    if inspect.state.as_ref().and_then(|state| state.paused) == Some(true) {
                        return self
                            .docker
                            .unpause_container(self.id.as_str())
                            .await
                            .map_err(|error| docker_error("unpausing container", error));
                    }
                    // Already-running (304) is success; a vanished container is
                    // not — start's postcondition is a running sandbox, so 404
                    // must surface, unlike stop/delete where gone is the goal.
                    match self
                        .docker
                        .start_container(self.id.as_str(), None::<StartContainerOptions<String>>)
                        .await
                    {
                        Ok(()) => Ok(()),
                        Err(error) if is_not_modified(&error) => Ok(()),
                        Err(error) if is_not_found(&error) => Err(Error::NotFound {
                            resource: ResourceKind::Sandbox,
                            id:       self.id.as_str().to_owned(),
                        }),
                        Err(error) => Err(docker_error("starting container", error)),
                    }
                },
            )
            .await
    }

    #[tracing::instrument(skip_all, fields(provider_kind = "docker", sandbox_id = %self.id), err)]
    async fn stop(&self) -> Result<()> {
        // Managed containers run the driver's own `sleep infinity` init
        // as PID1, which never installs a SIGTERM handler and (as PID1)
        // never receives the default disposition — so any stop grace is
        // waited out in full, buying nothing. Workload processes get
        // their SIGTERM-grace-SIGKILL sequence from the exec watcher,
        // not from `docker stop`. Keep the grace at fabro's 1 second.
        self.events
            .run(
                EventSubject::sandbox(Some(self.id.clone())),
                Action::Stop,
                |_| async {
                    tolerate_not_modified(
                        self.docker
                            .stop_container(self.id.as_str(), Some(StopContainerOptions { t: 1 }))
                            .await,
                        "stopping container",
                    )
                },
            )
            .await
    }

    #[tracing::instrument(skip_all, fields(provider_kind = "docker", sandbox_id = %self.id), err)]
    async fn delete(&self) -> Result<()> {
        let options = RemoveContainerOptions {
            force: true,
            ..Default::default()
        };
        self.events
            .run(
                EventSubject::sandbox(Some(self.id.clone())),
                Action::Delete,
                |_| async {
                    match self
                        .docker
                        .remove_container(self.id.as_str(), Some(options))
                        .await
                    {
                        Ok(()) => Ok(()),
                        Err(error) if is_not_found(&error) => Ok(()),
                        Err(error) => Err(docker_error("removing container", error)),
                    }
                },
            )
            .await
    }

    #[tracing::instrument(skip_all, fields(provider_kind = "docker", sandbox_id = %self.id), err)]
    async fn pause(&self) -> Result<()> {
        self.events
            .run(
                EventSubject::sandbox(Some(self.id.clone())),
                Action::Pause,
                |_| async {
                    self.docker
                        .pause_container(self.id.as_str())
                        .await
                        .map_err(|error| docker_error("pausing container", error))
                },
            )
            .await
    }

    #[tracing::instrument(skip_all, fields(provider_kind = "docker", sandbox_id = %self.id), err)]
    async fn resume(&self) -> Result<()> {
        self.events
            .run(
                EventSubject::sandbox(Some(self.id.clone())),
                Action::Resume,
                |_| async {
                    self.docker
                        .unpause_container(self.id.as_str())
                        .await
                        .map_err(|error| docker_error("unpausing container", error))
                },
            )
            .await
    }

    fn exec(&self) -> &dyn Exec {
        self.exec.as_ref()
    }

    fn fs(&self) -> &dyn Filesystem {
        &self.fs
    }

    fn pty(&self) -> Option<&dyn Pty> {
        Some(&self.pty)
    }

    fn shell_command(&self) -> Option<&dyn ShellCommand> {
        Some(&self.shell_command)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn image_spec() -> SandboxSpec {
        SandboxSpec::new(SandboxSource::Image {
            reference: "debian:stable-slim".to_owned(),
        })
    }

    fn assert_invalid_field(spec: &SandboxSpec, expected_field: &str) {
        let error = validate_supported_creation_fields(spec)
            .expect_err("unsupported field should fail validation");
        assert!(
            matches!(&error, Error::InvalidSpec { field, .. } if field == expected_field),
            "expected InvalidSpec for {expected_field}, got {error}"
        );
    }

    #[test]
    fn pull_options_default_a_bare_reference_to_latest() {
        let options = pull_options("ubuntu");
        assert_eq!(options.from_image, "ubuntu");
        assert_eq!(options.tag, "latest");
    }

    #[test]
    fn pull_options_split_an_explicit_tag() {
        let options = pull_options("debian:stable-slim");
        assert_eq!(options.from_image, "debian");
        assert_eq!(options.tag, "stable-slim");
    }

    #[test]
    fn pull_options_treat_a_registry_port_as_untagged() {
        let options = pull_options("registry:5000/img");
        assert_eq!(options.from_image, "registry:5000/img");
        assert_eq!(options.tag, "latest");
    }

    #[test]
    fn pull_options_pass_digest_references_through() {
        let options = pull_options("img@sha256:abc123");
        assert_eq!(options.from_image, "img@sha256:abc123");
        assert_eq!(options.tag, "");
    }

    #[test]
    fn unsupported_creation_fields_return_invalid_spec() {
        let mut spec = image_spec();
        spec.resources.disk_mb = Some(1024);
        assert_invalid_field(&spec, "resources.disk_mb");

        let mut spec = image_spec();
        spec.resources.gpus = Some(1);
        assert_invalid_field(&spec, "resources.gpus");

        let mut spec = image_spec();
        spec.user = Some("sandbox".to_owned());
        assert_invalid_field(&spec, "user");

        let mut spec = image_spec();
        spec.timers.auto_stop_after_idle = Some(Duration::from_secs(60));
        assert_invalid_field(&spec, "timers");

        let mut spec = image_spec();
        spec.ephemeral = true;
        assert_invalid_field(&spec, "ephemeral");

        let mut spec = image_spec();
        spec.public = Some(false);
        assert_invalid_field(&spec, "public");

        let mut spec = image_spec();
        spec.region = Some("local".to_owned());
        assert_invalid_field(&spec, "region");
    }

    #[test]
    fn supported_cpu_and_memory_requests_pass_creation_field_validation() {
        let mut spec = image_spec();
        spec.resources.cpu_cores = Some(2);
        spec.resources.memory_mb = Some(4096);
        validate_supported_creation_fields(&spec).expect("CPU and memory are supported");
    }
}
