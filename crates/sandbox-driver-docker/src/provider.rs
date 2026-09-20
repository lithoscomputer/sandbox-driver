//! The Docker provider: the daemon connection, image readiness, and the
//! verbs that create, attach to, list, and delete sandboxes.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use async_trait::async_trait;
use bollard::Docker;
use bollard::container::{
    Config, CreateContainerOptions, InspectContainerOptions, ListContainersOptions,
    RemoveContainerOptions, StartContainerOptions,
};
use bollard::models::{
    ContainerInspectResponse, EndpointSettings, HostConfig, Mount, MountTypeEnum,
};
use bollard::network::{ConnectNetworkOptions, DisconnectNetworkOptions};
use sandbox_driver::{
    Action, BASH_ENV_VAR, Capabilities, Error, EventContext, EventEmitter, EventSubject, Exec,
    HealthStatus, LifecycleTimers, NetworkPolicy, OperationReporter, Progress, ProgressCode,
    ProviderError, ProviderHealth, ProviderKind, ResourceKind, Result, Sandbox, SandboxFilter,
    SandboxId, SandboxKind, SandboxProvider, SandboxSource, SandboxSpec, SandboxState,
    SandboxStatus,
};
use serde::Deserialize;

use crate::access::DockerShellCommand;
use crate::config::{DockerProviderConfig, RegistryAuth};
use crate::daemon::{POSIX_SH, docker_error, docker_kind, is_conflict, is_not_found, shell_quote};
use crate::exec::DockerExec;
use crate::forward::DockerForwards;
use crate::fs::DockerFs;
use crate::image::{image_present, pull_image};
use crate::inspect::{
    is_internal_label, is_managed, map_state, normalized_container_name, sidecar_network_of,
    status_from_inspect, workspace_of,
};
use crate::one_shot::{self, DockerOneShot};
use crate::pty::DockerPty;
use crate::sandbox::DockerSandbox;
use crate::{
    DEFAULT_WORKING_DIRECTORY, MANAGED_LABEL, RUNTIME_DIRECTORY, RUNTIME_DIRECTORY_PARENT,
    SIDECAR_NETWORK_LABEL, docker_capabilities, non_empty, sidecars,
};

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
        Ok(Self::from_client(docker))
    }

    /// Use a caller-configured daemon connection, including an authenticated
    /// custom transport. This does not contact the daemon;
    /// [`SandboxProvider::health`] verifies the connection. The caller owns
    /// endpoint and TLS configuration.
    pub fn from_client(docker: Docker) -> Self {
        Self {
            kind: docker_kind(),
            capabilities: docker_capabilities(),
            docker,
        }
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
        let forwards = DockerForwards::new(Arc::clone(&exec));
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
            forwards,
            network,
            events,
        })
    }
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
        let base_network = if config_options.host_network {
            if !matches!(
                spec.network,
                NetworkPolicy::ProviderDefault | NetworkPolicy::AllowAll
            ) || !config_options.sidecars.is_empty()
            {
                return Err(Error::invalid_spec(
                    "provider_config.host_network",
                    "host networking requires unrestricted networking and no sidecars",
                ));
            }
            Some("host".to_owned())
        } else {
            network_mode(&spec.network)?
        };
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
                    if let Some(network) = &sidecar_network {
                        labels.insert(SIDECAR_NETWORK_LABEL.to_owned(), network.clone());
                    }

                    // The primary image is ready; map its container options.
                    let DockerProviderConfig {
                        init,
                        privileged,
                        binds,
                        extra_hosts,
                        dns,
                        cap_add,
                        ..
                    } = config_options;
                    // The labeled primary must exist before any dependent
                    // resource. Keep it stopped and isolated while preparing
                    // its network; the label records cleanup identity even
                    // before the container joins that network.
                    let network_mode = if sidecar_network.is_some() {
                        Some("none".to_owned())
                    } else {
                        base_network
                    };
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
                    // A failure cleans dependencies before the primary so
                    // unsuccessful cleanup remains discoverable by label.
                    let cleanup_network = &sidecar_network;
                    let sweep_on_error = |error: Error, container: Option<String>| async move {
                        if let Some(container) = container {
                            if let Some(network) = cleanup_network {
                                if let Err(cleanup_error) = sidecars::sweep(&self.docker, network, Some(&container)).await {
                                    tracing::warn!(error = %cleanup_error, "failed sandbox sidecar cleanup failed; primary retained for retry");
                                    return error;
                                }
                            }
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
                    if let Some(network) = &sidecar_network {
                        let prepare = async {
                            sidecars::realize(&self.docker, network, &config_options.sidecars).await?;
                            self.docker.disconnect_network("none", DisconnectNetworkOptions {
                                container: created.id.as_str(), force: true,
                            }).await.map_err(|error| docker_error("disconnecting initial sandbox network", error))?;
                            self.docker.connect_network(network, ConnectNetworkOptions {
                                container: created.id.as_str(), endpoint_config: EndpointSettings::default(),
                            }).await.map_err(|error| docker_error("connecting sandbox to services", error))
                        }.await;
                        if let Err(error) = prepare {
                            return Err(sweep_on_error(error, Some(created.id.clone())).await);
                        }
                    }
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
                    one_shot::sweep(&self.docker, &container_id).await?;
                    if let Some(network) = &network {
                        sidecars::sweep(&self.docker, network, Some(&container_id)).await?;
                    }
                    let options = RemoveContainerOptions {
                        force: true,
                        v: true,
                        ..Default::default()
                    };
                    match self
                        .docker
                        .remove_container(&container_id, Some(options))
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

#[cfg(test)]
mod tests {
    use std::time::Duration;

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
