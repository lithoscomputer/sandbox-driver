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
//! without it fails every exec with a clear message).
//!
//! # Runtime behavior
//!
//! Async on Tokio; the caller owns the runtime. Spawned tasks: stream
//! demux and stdin writers scoped to a running exec, and kill requests
//! on cancellation that run from `/` and fail loudly when the stop
//! cannot be requested. Docker itself is the
//! sandbox registry — handles re-attach by container id across process
//! restarts.

mod exec;
mod fs;

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::{Duration, Instant};

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
    Capabilities, Error, ErrorReport, EventCallback, EventDispatcher, Exec, ExecSpec, Filesystem,
    Isolation, LifecycleAction, NetworkPolicy, PlatformInfo, ProviderKind, ResourceKind, Result,
    Sandbox, SandboxEvent, SandboxFilter, SandboxId, SandboxProvider, SandboxSource, SandboxSpec,
    SandboxState, SandboxStatus,
};

pub use crate::exec::DockerExec;
use crate::exec::{
    BASH_ENV_VAR, docker_error, is_not_found, is_not_modified, shell_quote, tolerate_not_modified,
};
use crate::fs::DockerFs;

const MANAGED_LABEL: &str = "sh.sandbox-driver.managed";
const DEFAULT_WORKING_DIRECTORY: &str = "/workspace";

/// The Docker provider. One per process, sharing one daemon connection.
pub struct DockerProvider {
    kind:         ProviderKind,
    capabilities: Capabilities,
    docker:       Docker,
}

impl DockerProvider {
    /// Connects to the local Docker daemon and verifies it responds.
    pub async fn connect() -> Result<Self> {
        let docker = Docker::connect_with_local_defaults()
            .map_err(|error| docker_error("connecting to the docker daemon", &error))?;
        docker
            .ping()
            .await
            .map_err(|error| docker_error("pinging the docker daemon", &error))?;
        Ok(Self {
            kind: ProviderKind::try_new("docker").expect("static kind is valid"),
            capabilities: docker_capabilities(),
            docker,
        })
    }

    async fn ensure_image(
        &self,
        reference: &str,
        dispatcher: Option<&EventDispatcher>,
    ) -> Result<()> {
        match self.docker.inspect_image(reference).await {
            Ok(_) => return Ok(()),
            // Only a definitive "not present" justifies a pull; a daemon
            // or transport failure must surface as what it is.
            Err(error) if is_not_found(&error) => {}
            Err(error) => return Err(docker_error("inspecting image", &error)),
        }
        if let Some(dispatcher) = dispatcher {
            dispatcher
                .emit(SandboxEvent::Progress {
                    action:  LifecycleAction::Create,
                    message: format!("pulling image {reference}"),
                })
                .await;
        }
        let mut stream = self
            .docker
            .create_image(Some(pull_options(reference)), None, None);
        while let Some(progress) = stream.next().await {
            progress.map_err(|error| docker_error("pulling image", &error))?;
        }
        Ok(())
    }

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
                    docker_error("inspecting container", &error)
                }
            })
    }

    fn handle(
        &self,
        container_id: String,
        working_dir: String,
        labels: BTreeMap<String, String>,
        env: BTreeMap<String, String>,
        events: Option<EventCallback>,
    ) -> Arc<DockerSandbox> {
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
            capabilities: self.capabilities.clone(),
            docker: self.docker.clone(),
            working_dir,
            labels,
            exec,
            fs,
            dispatcher: events.map(EventDispatcher::new),
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
    caps.fs.native = false;
    caps.fs.upload = true;
    caps.fs.download = true;
    caps.fs.permissions = true;
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

#[async_trait]
impl SandboxProvider for DockerProvider {
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
        let network = network_mode(&spec.network)?;

        let dispatcher = events.map(EventDispatcher::new);
        if let Some(dispatcher) = &dispatcher {
            dispatcher
                .emit(SandboxEvent::ActionStarted {
                    action: LifecycleAction::Create,
                })
                .await;
        }
        let started = Instant::now();
        // Every failure after ActionStarted must pair with ActionFailed;
        // the fallible section funnels through one outcome.
        let outcome = async {
            self.ensure_image(reference, dispatcher.as_ref()).await?;

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
                        "mkdir -p {} && exec sleep infinity",
                        shell_quote(&working_dir)
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
                .map_err(|error| docker_error("creating container", &error))?;
            self.docker
                .start_container(&created.id, None::<StartContainerOptions<String>>)
                .await
                .map_err(|error| docker_error("starting container", &error))?;
            Ok::<_, Error>((created.id, working_dir))
        }
        .await;
        let (container_id, working_dir) = match outcome {
            Ok(parts) => parts,
            Err(error) => {
                if let Some(dispatcher) = &dispatcher {
                    dispatcher
                        .emit(SandboxEvent::ActionFailed {
                            action: LifecycleAction::Create,
                            error:  ErrorReport::from(&error),
                        })
                        .await;
                }
                return Err(error);
            }
        };

        let handle = self.handle(
            container_id,
            working_dir,
            spec.labels.clone(),
            spec.env.clone(),
            None,
        );
        if let Some(dispatcher) = dispatcher {
            dispatcher
                .emit(SandboxEvent::ActionCompleted {
                    action:   LifecycleAction::Create,
                    duration: started.elapsed(),
                })
                .await;
            // Hand the dispatcher to the sandbox for its later actions.
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
            working_dir,
            user_labels,
            BTreeMap::new(),
            events,
        ))
    }

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
            .map_err(|error| docker_error("listing containers", &error))?;
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
    id:           SandboxId,
    capabilities: Capabilities,
    docker:       Docker,
    working_dir:  String,
    labels:       BTreeMap<String, String>,
    exec:         Arc<DockerExec>,
    fs:           DockerFs,
    dispatcher:   Option<EventDispatcher>,
}

impl DockerSandbox {
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
impl Sandbox for DockerSandbox {
    fn id(&self) -> &SandboxId {
        &self.id
    }

    fn capabilities(&self) -> &Capabilities {
        &self.capabilities
    }

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
                Ok(SandboxStatus::new(self.id.clone(), SandboxState::Deleted))
            }
            Err(error) => Err(docker_error("inspecting container", &error)),
        }
    }

    fn working_directory(&self) -> &str {
        &self.working_dir
    }

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

    async fn start(&self) -> Result<()> {
        let inspect = self
            .docker
            .inspect_container(self.id.as_str(), None::<InspectContainerOptions>)
            .await
            .map_err(|error| docker_error("inspecting container", &error))?;
        let outcome = if inspect.state.as_ref().and_then(|state| state.paused) == Some(true) {
            self.docker
                .unpause_container(self.id.as_str())
                .await
                .map_err(|error| docker_error("unpausing container", &error))
        } else {
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
                Err(error) => Err(docker_error("starting container", &error)),
            }
        };
        self.emit_action(LifecycleAction::Start, &outcome).await;
        outcome
    }

    async fn stop(&self) -> Result<()> {
        // Managed containers run the driver's own `sleep infinity` init
        // as PID1, which never installs a SIGTERM handler and (as PID1)
        // never receives the default disposition — so any stop grace is
        // waited out in full, buying nothing. Workload processes get
        // their SIGTERM-grace-SIGKILL sequence from the exec watcher,
        // not from `docker stop`. Keep the grace at fabro's 1 second.
        let outcome = tolerate_not_modified(
            self.docker
                .stop_container(self.id.as_str(), Some(StopContainerOptions { t: 1 }))
                .await,
            "stopping container",
        );
        self.emit_action(LifecycleAction::Stop, &outcome).await;
        outcome
    }

    async fn delete(&self) -> Result<()> {
        let options = RemoveContainerOptions {
            force: true,
            ..Default::default()
        };
        let outcome = match self
            .docker
            .remove_container(self.id.as_str(), Some(options))
            .await
        {
            Ok(()) => Ok(()),
            Err(error) if is_not_found(&error) => Ok(()),
            Err(error) => Err(docker_error("removing container", &error)),
        };
        self.emit_action(LifecycleAction::Delete, &outcome).await;
        outcome
    }

    async fn pause(&self) -> Result<()> {
        let outcome = self
            .docker
            .pause_container(self.id.as_str())
            .await
            .map_err(|error| docker_error("pausing container", &error));
        self.emit_action(LifecycleAction::Pause, &outcome).await;
        outcome
    }

    async fn resume(&self) -> Result<()> {
        let outcome = self
            .docker
            .unpause_container(self.id.as_str())
            .await
            .map_err(|error| docker_error("unpausing container", &error));
        self.emit_action(LifecycleAction::Resume, &outcome).await;
        outcome
    }

    fn exec(&self) -> &dyn Exec {
        self.exec.as_ref()
    }

    fn fs(&self) -> &dyn Filesystem {
        &self.fs
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
