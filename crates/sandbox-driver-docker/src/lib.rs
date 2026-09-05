//! Docker container sandbox provider.
//!
//! Containers created from OCI images, with kernel-sharing container
//! isolation (`Isolation::Container`). The Docker socket is
//! host-root-equivalent, so this provider is host-trusted by definition.
//!
//! The container's data plane is hybrid: file content moves through
//! the daemon's archive API (streamed reads that stop at the requested
//! range, writes that carry their missing parents, both working on a
//! stopped container), while metadata operations stay exec-derived — so
//! `Capabilities::fs` still reports `native: false`. Every image must
//! provide `/bin/sh`, `env`, and `setsid` for the exec wrapper (kill
//! semantics need a separate session, and `env` carries the command's
//! environment past the shell; an image without either fails every exec
//! with a clear message). The exec-derived facets are Bash scripts, so an
//! image that serves them must also provide `bash` on `PATH` and a Linux
//! userland with `stat`, `find`, and `base64`. Because Docker advertises
//! the normalized Search, Git, and background-services facets, the image
//! must also provide the commands documented by [`sandbox_driver::Search`]
//! and [`sandbox_driver::Services`], plus `git`, on `PATH`. A program that
//! needs none of that — Petri's step runner, which execs, reads and writes
//! files, and runs one-shot containers — runs on any Linux image with a
//! POSIX userland, Alpine included.
//!
//! # The workspace
//!
//! The sandbox owns its workspace: the working directory is a Docker
//! volume created with the container and removed with it, unless the
//! caller's `provider_config.binds` mounts a host directory there. Every
//! [`sandbox_driver::OneShot`] container the sandbox runs mounts the same
//! volume at the same path and joins the sandbox container's network
//! namespace, so it sees the workspace, the sidecars, and the daemon host
//! exactly as the sandbox does. `stop` and `delete` end the sandbox's
//! one-shot containers first.
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
mod config;
mod exec;
mod fs;
mod one_shot;
mod pty;
mod sidecars;

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
use bollard::models::{
    ContainerInspectResponse, ContainerStateStatusEnum, HostConfig, Mount, MountPointTypeEnum,
    MountTypeEnum,
};
use futures_util::StreamExt;
use sandbox_driver::{
    Action, BASH_ENV_VAR, Capabilities, Error, EventContext, EventEmitter, EventSubject, Exec,
    ExecSpec, Filesystem, HealthStatus, Isolation, LifecycleTimers, NetworkPolicy, OneShot,
    OneShotCaps, OperationReporter, PlatformInfo, Progress, ProgressCode, ProviderError,
    ProviderHealth, ProviderKind, Pty, PtyCaps, ResourceKind, Result, Sandbox, SandboxFilter,
    SandboxId, SandboxKind, SandboxProvider, SandboxSource, SandboxSpec, SandboxState,
    SandboxStatus, ShellCommand,
};
use serde::Deserialize;

use crate::access::DockerShellCommand;
pub use crate::config::{BindMount, DockerProviderConfig, Health, RegistryAuth, Sidecar};
pub use crate::exec::DockerExec;
use crate::exec::{
    POSIX_SH, docker_error, docker_kind, is_conflict, is_not_found, is_not_modified, shell_quote,
    tolerate_not_modified,
};
use crate::fs::DockerFs;
use crate::one_shot::DockerOneShot;
use crate::pty::DockerPty;

pub(crate) const MANAGED_LABEL: &str = "sh.sandbox-driver.managed";
const DEFAULT_WORKING_DIRECTORY: &str = "/workspace";
const RUNTIME_DIRECTORY_PARENT: &str = "/tmp/sandbox-driver";
pub(crate) const RUNTIME_DIRECTORY: &str = "/tmp/sandbox-driver/runtime";

/// `Some(items)` when there are any; Docker's optional list fields read
/// an empty list and an absent one the same way, so the absent form is
/// the cleaner request.
pub(crate) fn non_empty<T>(items: Vec<T>) -> Option<Vec<T>> {
    (!items.is_empty()).then_some(items)
}

/// Parses `SandboxSpec::provider_config` as [`DockerProviderConfig`]:
/// `null` is the default, an object is validated, anything else is
/// rejected.
fn provider_config(value: &serde_json::Value) -> Result<DockerProviderConfig> {
    match value {
        serde_json::Value::Null => Ok(DockerProviderConfig::default()),
        serde_json::Value::Object(_) => DockerProviderConfig::deserialize(value)
            .map_err(|error| Error::invalid_spec("provider_config", error.to_string())),
        _ => Err(Error::invalid_spec("provider_config", "expected an object")),
    }
}

/// Whether the daemon has `reference` locally. Only a definitive "not
/// present" is `false`; a daemon or transport failure surfaces as what
/// it is.
pub(crate) async fn image_present(docker: &Docker, reference: &str) -> Result<bool> {
    match docker.inspect_image(reference).await {
        Ok(_) => Ok(true),
        Err(error) if is_not_found(&error) => Ok(false),
        Err(error) => Err(docker_error("inspecting image", error)),
    }
}

/// Pulls an image, using registry credentials when given, and waits for
/// the pull to finish. Shared by the main-image path and sidecars.
pub(crate) async fn pull_image(
    docker: &Docker,
    reference: &str,
    auth: Option<&RegistryAuth>,
    platform: Option<&str>,
) -> Result<()> {
    let credentials = auth.map(config::to_credentials);
    let mut stream =
        docker.create_image(Some(pull_options(reference, platform)), None, credentials);
    while let Some(progress) = stream.next().await {
        progress.map_err(|error| docker_error("pulling image", error))?;
    }
    Ok(())
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
        let provider = Self::connect_unverified()?;
        provider
            .docker
            .ping()
            .await
            .map_err(|error| docker_error("pinging the docker daemon", error))?;
        Ok(provider)
    }

    /// Connects to the local Docker daemon (`DOCKER_HOST` and its TLS
    /// companions honoured) without checking that it answers, so a plugin
    /// can start and report an unreachable daemon through
    /// [`SandboxProvider::health`] instead of failing to launch.
    pub fn connect_unverified() -> Result<Self> {
        let docker = Docker::connect_with_local_defaults()
            .map_err(|error| docker_error("connecting to the docker daemon", error))?;
        Ok(Self {
            kind: docker_kind(),
            capabilities: docker_capabilities(),
            docker,
        })
    }

    #[tracing::instrument(skip_all, fields(provider_kind = %self.kind), err)]
    async fn ensure_image(
        &self,
        reference: &str,
        auto_pull: bool,
        auth: Option<&RegistryAuth>,
        platform: Option<&str>,
        reporter: &OperationReporter,
    ) -> Result<()> {
        if image_present(&self.docker, reference).await? {
            return Ok(());
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
        pull_image(&self.docker, reference, auth, platform).await
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

    /// Builds a handle from Docker state alone: no exec runs here, so
    /// `attach` works on a stopped container too.
    fn handle(
        &self,
        container_id: String,
        name: Option<String>,
        working_dir: String,
        labels: BTreeMap<String, String>,
        env: BTreeMap<String, String>,
        network: Option<String>,
        workspace: Option<Mount>,
        events: EventEmitter,
    ) -> Arc<DockerSandbox> {
        let pty = DockerPty::new(
            self.docker.clone(),
            container_id.clone(),
            working_dir.clone(),
        );
        let one_shot = workspace.map(|workspace| {
            DockerOneShot::new(
                self.docker.clone(),
                container_id.clone(),
                working_dir.clone(),
                workspace,
            )
        });
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
            one_shot,
            network,
            events,
        })
    }
}

/// Splits an image reference for the pull API. An empty tag pulls every
/// tag of the repository, so bare references default to `latest`; digest
/// references pass through whole.
fn pull_options(reference: &str, platform: Option<&str>) -> CreateImageOptions<'static, String> {
    let platform = platform.unwrap_or_default().to_owned();
    if reference.contains('@') {
        return CreateImageOptions {
            from_image: reference.to_owned(),
            platform,
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
        platform,
        ..Default::default()
    }
}

fn docker_capabilities() -> Capabilities {
    let mut caps = Capabilities::minimal(Isolation::Container);
    caps.lifecycle.pause = true;
    caps.exec.live_streaming = true;
    caps.exec.streams_separated = true;
    caps.exec.stdin = true;
    caps.exec.stdin_stream = true;
    caps.exec.stop = true;
    caps.exec.stdio_process = true;
    caps.exec.environment = true;
    let mut pty = PtyCaps::default();
    pty.resize = true;
    caps.pty = Some(pty);
    caps.access.shell_command = true;
    let mut one_shot = OneShotCaps::default();
    one_shot.build = true;
    caps.one_shot = Some(one_shot);
    caps.fs.native = false;
    caps.fs.upload = true;
    caps.fs.download = true;
    caps.fs.permissions = true;
    caps.search.supported = true;
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
                .filter(|(key, _)| !is_internal_label(key))
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect();
        }
        status.source.clone_from(&config.image);
    }
    status
}

/// Whether an inspected container is one this provider created. Anything
/// else is not a sandbox, whatever else it is.
fn is_managed(inspect: &ContainerInspectResponse) -> bool {
    inspect
        .config
        .as_ref()
        .and_then(|config| config.labels.as_ref())
        .and_then(|labels| labels.get(MANAGED_LABEL))
        .map(String::as_str)
        == Some("true")
}

/// The managed sidecar network an inspected container joined, if any: a
/// user-defined network named after the sandbox, recovered from the
/// container's network mode so a rebuilt handle or a delete by id sweeps
/// the sidecars too.
fn sidecar_network_of(inspect: &ContainerInspectResponse) -> Option<String> {
    inspect
        .host_config
        .as_ref()
        .and_then(|host| host.network_mode.clone())
        .filter(|mode| is_sidecar_network(mode))
}

/// Where an inspected container's workspace lives: the volume or bind
/// mounted at its working directory, which its one-shot containers share.
fn workspace_of(inspect: &ContainerInspectResponse, working_dir: &str) -> Option<Mount> {
    let target = working_dir.trim_end_matches('/');
    inspect.mounts.as_ref()?.iter().find_map(|mount| {
        let destination = mount.destination.as_deref()?.trim_end_matches('/');
        if destination != target {
            return None;
        }
        let (typ, source) = match mount.typ {
            Some(MountPointTypeEnum::VOLUME) => (MountTypeEnum::VOLUME, mount.name.clone()?),
            Some(MountPointTypeEnum::BIND) => (MountTypeEnum::BIND, mount.source.clone()?),
            _ => return None,
        };
        Some(Mount {
            target: Some(working_dir.to_owned()),
            source: Some(source),
            typ: Some(typ),
            read_only: mount.rw.map(|writable| !writable),
            ..Default::default()
        })
    })
}

/// Labels the provider writes for itself, never reported as the caller's.
fn is_internal_label(key: &str) -> bool {
    key == MANAGED_LABEL || key == one_shot::ONE_SHOT_LABEL
}

/// Whether a container's network mode names a managed sidecar network
/// (`<sandbox>-net`) rather than a standard Docker mode or another
/// container's namespace.
fn is_sidecar_network(mode: &str) -> bool {
    mode.ends_with("-net") && !mode.starts_with("container:")
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
        let base_network = network_mode(&spec.network)?;
        // Sidecars live on one user-defined network the main container
        // joins, named after the sandbox. They need a named sandbox.
        let sidecar_network = if config_options.sidecars.is_empty() {
            None
        } else {
            let name = spec.name.clone().ok_or_else(|| {
                Error::invalid_spec("name", "a sandbox with sidecars must be named")
            })?;
            Some(format!("{name}-net"))
        };

        let emitter = EventEmitter::new(self.kind.clone(), events);
        let handle_emitter = emitter.clone();
        emitter
            .run(
                EventSubject::pending_sandbox(spec.name.clone()),
                Action::Create,
                |reporter| async move {
                    self.ensure_image(
                        reference,
                        config_options.auto_pull,
                        config_options.registry_auth.as_ref(),
                        config_options.platform.as_deref(),
                        &reporter,
                    )
                    .await?;

                    // Sidecars come up healthy before the main container, so
                    // a workload never races a service that is not ready.
                    if let Some(network) = &sidecar_network {
                        sidecars::realize(&self.docker, network, &config_options.sidecars).await?;
                    }

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

                    // The image and sidecars are up; the rest of the
                    // options belong to the main container.
                    let DockerProviderConfig {
                        init,
                        privileged,
                        binds,
                        extra_hosts,
                        dns,
                        cap_add,
                        ..
                    } = config_options;
                    let network_mode = sidecar_network.clone().or(base_network);
                    // The workspace is the sandbox's own volume, unless the
                    // caller bound a host directory there.
                    let workspace_bound = binds.iter().any(|bind| {
                        bind.container.trim_end_matches('/') == working_dir.trim_end_matches('/')
                    });
                    let mounts = (!workspace_bound).then(|| {
                        vec![Mount {
                            target: Some(working_dir.clone()),
                            typ: Some(MountTypeEnum::VOLUME),
                            ..Default::default()
                        }]
                    });
                    let binds: Vec<String> = binds
                        .iter()
                        .map(|bind| {
                            let mode = bind.mode.as_deref().unwrap_or("rw");
                            format!("{}:{}:{mode}", bind.host, bind.container)
                        })
                        .collect();
                    let host_config = HostConfig {
                        network_mode,
                        binds: non_empty(binds),
                        mounts,
                        init: init.then_some(true),
                        privileged: privileged.then_some(true),
                        extra_hosts: non_empty(extra_hosts),
                        dns: non_empty(dns),
                        cap_add: non_empty(cap_add),
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
                    // The init script is POSIX and runs under /bin/sh, which
                    // every Linux image has.
                    let config = Config {
                        image: Some(reference.clone()),
                        user: spec.user.clone(),
                        cmd: Some(vec![
                            POSIX_SH.to_owned(),
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
                    let options =
                        (spec.name.is_some() || config_options.platform.is_some()).then(|| {
                            CreateContainerOptions {
                                name:     spec.name.clone().unwrap_or_default(),
                                platform: config_options.platform.clone(),
                            }
                        });
                    // From here a failure must sweep the sidecars it started.
                    let cleanup_network = &sidecar_network;
                    let sweep_on_error = |error: Error, container: Option<String>| async move {
                        if let Some(container) = container {
                            if let Err(cleanup_error) = self.docker.remove_container(
                                &container,
                                Some(RemoveContainerOptions {
                                    force: true,
                                    v: true,
                                    ..Default::default()
                                }),
                            ).await {
                                if !is_not_found(&cleanup_error) {
                                    tracing::warn!(
                                        provider_kind = "docker",
                                        error = %docker_error("removing failed sandbox", cleanup_error),
                                        "failed sandbox cleanup failed"
                                    );
                                }
                            }
                        }
                        if let Some(network) = cleanup_network {
                            sidecars::sweep(&self.docker, network).await;
                        }
                        error
                    };
                    let created = match self.docker.create_container(options, config).await {
                        Ok(created) => created,
                        Err(error) => {
                            let error = if is_conflict(&error) && spec.name.is_some() {
                                Error::invalid_spec(
                                    "name",
                                    "a container with this name already exists",
                                )
                            } else {
                                docker_error("creating container", error)
                            };
                            return Err(sweep_on_error(error, None).await);
                        }
                    };
                    let event_id = match SandboxId::try_new(created.id.clone()) {
                        Ok(id) => id,
                        Err(error) => return Err(sweep_on_error(
                            Error::invalid_spec("sandbox_id", error.to_string()),
                            Some(created.id.clone()),
                        ).await),
                    };
                    reporter.set_subject(EventSubject::sandbox(Some(event_id)));
                    if let Err(error) = self
                        .docker
                        .start_container(&created.id, None::<StartContainerOptions<String>>)
                        .await
                    {
                        return Err(sweep_on_error(docker_error("starting container", error), Some(created.id.clone())).await);
                    }
                    // `start` returning is not the container running: an init
                    // that exits at once (a missing interpreter, a bad user)
                    // leaves a stopped container every exec would then 409 on.
                    // Fail create instead, naming the cause.
                    let started = match self.inspect(&created.id).await {
                        Ok(inspect) => inspect,
                        Err(error) => return Err(sweep_on_error(error, Some(created.id.clone())).await),
                    };
                    if map_state(&started) != SandboxState::Running {
                        let exit = started
                            .state
                            .as_ref()
                            .and_then(|state| state.exit_code)
                            .unwrap_or_default();
                        let mut provider = ProviderError::new(
                            self.kind.clone(),
                            format!(
                                "container exited immediately after start (exit code {exit}); \
                                 the image must run its init under /bin/sh as the configured user"
                            ),
                        );
                        provider.code = Some("exited".to_owned());
                        return Err(sweep_on_error(Error::Provider(provider), Some(created.id.clone())).await);
                    }
                    let workspace = workspace_of(&started, &working_dir);
                    Ok(self.handle(
                        created.id,
                        spec.name.clone(),
                        working_dir,
                        spec.labels.clone(),
                        spec.env.clone(),
                        sidecar_network.clone(),
                        workspace,
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
                    if !is_managed(&inspect) {
                        return Err(Error::NotFound {
                            resource: ResourceKind::Sandbox,
                            id:       id.as_str().to_owned(),
                        });
                    }
                    let config = inspect.config.as_ref();
                    let labels = config.and_then(|config| config.labels.as_ref());
                    let working_dir = config
                        .and_then(|config| config.working_dir.clone())
                        .unwrap_or_else(|| DEFAULT_WORKING_DIRECTORY.to_owned());
                    let user_labels: BTreeMap<String, String> = labels
                        .map(|labels| {
                            labels
                                .iter()
                                .filter(|(key, _)| !is_internal_label(key))
                                .map(|(key, value)| (key.clone(), value.clone()))
                                .collect()
                        })
                        .unwrap_or_default();
                    let network = sidecar_network_of(&inspect);
                    let workspace = workspace_of(&inspect, &working_dir);
                    let container_id = inspect.id.clone().unwrap_or_else(|| id.as_str().to_owned());
                    Ok(self.handle(
                        container_id,
                        normalized_container_name(inspect.name.as_deref()),
                        working_dir,
                        user_labels,
                        BTreeMap::new(),
                        network,
                        workspace,
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
    async fn delete(&self, id: &SandboxId, events: Option<EventContext>) -> Result<()> {
        let emitter = EventEmitter::new(self.kind.clone(), events);
        emitter
            .run(
                EventSubject::sandbox(Some(id.clone())),
                Action::Delete,
                |_| async move {
                    // Docker state alone decides what to remove: no handle
                    // and no exec, so a stopped or wedged container goes the
                    // same way as a running one.
                    let inspect = match self.inspect(id.as_str()).await {
                        Ok(inspect) => inspect,
                        Err(Error::NotFound { .. }) => return Ok(()),
                        Err(error) => return Err(error),
                    };
                    // A container this provider did not create is unknown to
                    // it, and deleting an unknown id succeeds by doing nothing.
                    if !is_managed(&inspect) {
                        return Ok(());
                    }
                    let network = sidecar_network_of(&inspect);
                    let container_id = inspect.id.clone().unwrap_or_else(|| id.as_str().to_owned());
                    // One-shot containers hold the workspace volume too, so
                    // they go first and the volume goes with its last user.
                    one_shot::sweep(&self.docker, &container_id).await;
                    let options = RemoveContainerOptions {
                        force: true,
                        v: true,
                        ..Default::default()
                    };
                    let removed = match self
                        .docker
                        .remove_container(&container_id, Some(options))
                        .await
                    {
                        Ok(()) => Ok(()),
                        Err(error) if is_not_found(&error) => Ok(()),
                        Err(error) => Err(docker_error("removing container", error)),
                    };
                    if let Some(network) = &network {
                        sidecars::sweep(&self.docker, network).await;
                    }
                    removed
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
    /// One-shot containers over the sandbox's workspace, when the
    /// container's mounts told where that workspace is.
    one_shot:      Option<DockerOneShot>,
    /// The sidecar network to sweep on delete, when the sandbox has one.
    network:       Option<String>,
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
    async fn environment(&self) -> Result<BTreeMap<String, String>> {
        // The container's effective env is the image's plus what create
        // set, which the daemon records on `.Config.Env`. `BASH_ENV` is
        // an internal blank and never part of the reported environment.
        let inspect = self
            .docker
            .inspect_container(self.id.as_str(), None::<InspectContainerOptions>)
            .await
            .map_err(|error| docker_error("inspecting container", error))?;
        let entries = inspect
            .config
            .and_then(|config| config.env)
            .unwrap_or_default();
        let mut env = BTreeMap::new();
        for entry in entries {
            if let Some((key, value)) = entry.split_once('=') {
                if key != BASH_ENV_VAR {
                    env.insert(key.to_owned(), value.to_owned());
                }
            }
        }
        Ok(env)
    }

    #[tracing::instrument(skip_all, fields(provider_kind = "docker", sandbox_id = %self.id), err)]
    async fn platform_info(&self) -> Result<PlatformInfo> {
        // uname prints its fields in canonical order — sysname, release,
        // machine — regardless of flag order.
        let result = self
            .exec
            .run(
                &ExecSpec::new("uname")
                    .args(["-s", "-r", "-m"])
                    .timeout(Duration::from_secs(30)),
            )
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
                    if let Some(network) = &self.network {
                        sidecars::set_running(&self.docker, network, true).await?;
                    }
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
                    // Whatever a one-shot was doing in the workspace ends
                    // with the sandbox's own processes.
                    one_shot::sweep(&self.docker, self.id.as_str()).await;
                    tolerate_not_modified(
                        self.docker
                            .stop_container(self.id.as_str(), Some(StopContainerOptions { t: 1 }))
                            .await,
                        "stopping container",
                    )?;
                    if let Some(network) = &self.network {
                        sidecars::set_running(&self.docker, network, false).await?;
                    }
                    Ok(())
                },
            )
            .await
    }

    #[tracing::instrument(skip_all, fields(provider_kind = "docker", sandbox_id = %self.id), err)]
    async fn delete(&self) -> Result<()> {
        let options = RemoveContainerOptions {
            force: true,
            v: true,
            ..Default::default()
        };
        self.events
            .run(
                EventSubject::sandbox(Some(self.id.clone())),
                Action::Delete,
                |_| async {
                    one_shot::sweep(&self.docker, self.id.as_str()).await;
                    let removed = match self
                        .docker
                        .remove_container(self.id.as_str(), Some(options))
                        .await
                    {
                        Ok(()) => Ok(()),
                        Err(error) if is_not_found(&error) => Ok(()),
                        Err(error) => Err(docker_error("removing container", error)),
                    };
                    if let Some(network) = &self.network {
                        sidecars::sweep(&self.docker, network).await;
                    }
                    removed
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

    fn one_shot(&self) -> Option<&dyn OneShot> {
        self.one_shot
            .as_ref()
            .map(|one_shot| one_shot as &dyn OneShot)
    }

    fn shell_command(&self) -> Option<&dyn ShellCommand> {
        Some(&self.shell_command)
    }
}

#[cfg(test)]
mod tests {
    use bollard::models::MountPoint;

    use super::*;

    #[test]
    fn workspace_mount_preserves_read_only_access() {
        let inspect = ContainerInspectResponse {
            mounts: Some(vec![MountPoint {
                typ: Some(MountPointTypeEnum::BIND),
                source: Some("/tmp/workspace".to_owned()),
                destination: Some("/workspace".to_owned()),
                rw: Some(false),
                ..Default::default()
            }]),
            ..Default::default()
        };
        let mount = workspace_of(&inspect, "/workspace/").expect("workspace");
        assert_eq!(mount.source.as_deref(), Some("/tmp/workspace"));
        assert_eq!(mount.typ, Some(MountTypeEnum::BIND));
        assert_eq!(mount.read_only, Some(true));
    }

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
        let options = pull_options("ubuntu", None);
        assert_eq!(options.from_image, "ubuntu");
        assert_eq!(options.tag, "latest");
    }

    #[test]
    fn pull_options_split_an_explicit_tag() {
        let options = pull_options("debian:stable-slim", None);
        assert_eq!(options.from_image, "debian");
        assert_eq!(options.tag, "stable-slim");
    }

    #[test]
    fn pull_options_treat_a_registry_port_as_untagged() {
        let options = pull_options("registry:5000/img", None);
        assert_eq!(options.from_image, "registry:5000/img");
        assert_eq!(options.tag, "latest");
    }

    #[test]
    fn pull_options_pass_digest_references_through() {
        let options = pull_options("img@sha256:abc123", None);
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
