//! Sidecar service containers for a Docker sandbox.
//!
//! A sandbox that declares `provider_config.sidecars` gets one user-defined
//! network and one container per sidecar on it, reachable by `name` as a
//! network alias. The main container joins the same network, so a workload
//! reaches every sidecar by name. Sidecars carry a label naming the
//! network, so [`sweep`] and [`set_running`] find them again from a handle
//! rebuilt by `attach`, and `create` tears down what it started when any
//! sidecar fails.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use bollard::Docker;
use bollard::container::{
    Config, CreateContainerOptions, ListContainersOptions, NetworkingConfig,
    RemoveContainerOptions, StartContainerOptions, StopContainerOptions,
};
use bollard::models::{
    ContainerStateStatusEnum, EndpointSettings, HealthConfig, HealthStatusEnum, HostConfig,
};
use bollard::network::CreateNetworkOptions;
use sandbox_driver::{Error, ProviderError, Result};
use tokio::time;

use crate::exec::{docker_error, docker_kind, is_not_found, tolerate_not_modified};
use crate::{MANAGED_LABEL, RegistryAuth, image_present, non_empty, pull_image};

/// The label every sidecar carries, naming its network.
pub(crate) const NETWORK_LABEL: &str = "sh.sandbox-driver.network";
/// How long to wait for every sidecar to report healthy.
const HEALTH_WAIT: Duration = Duration::from_secs(300);
/// How often to poll a sidecar's health.
const HEALTH_POLL: Duration = Duration::from_millis(250);

/// One sidecar service, parsed from `provider_config.sidecars`.
#[derive(Clone, Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Sidecar {
    pub name:          String,
    pub image:         String,
    #[serde(default)]
    pub env:           HashMap<String, String>,
    #[serde(default)]
    pub dns:           Vec<String>,
    #[serde(default)]
    pub cap_add:       Vec<String>,
    pub user:          Option<String>,
    pub entrypoint:    Option<Vec<String>>,
    pub health:        Option<Health>,
    pub registry_auth: Option<RegistryAuth>,
}

/// A sidecar health check, mapped onto Docker's own.
#[derive(Clone, Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Health {
    /// The `CMD-SHELL` command, run by the container's default shell.
    pub cmd:             String,
    pub interval_ms:     Option<u64>,
    pub timeout_ms:      Option<u64>,
    pub retries:         Option<u64>,
    pub start_period_ms: Option<u64>,
}

fn ms_to_ns(ms: u64) -> i64 {
    i64::try_from(ms.saturating_mul(1_000_000)).unwrap_or(i64::MAX)
}

impl Health {
    fn to_config(&self) -> HealthConfig {
        HealthConfig {
            test:           Some(vec!["CMD-SHELL".to_owned(), self.cmd.clone()]),
            interval:       self.interval_ms.map(ms_to_ns),
            timeout:        self.timeout_ms.map(ms_to_ns),
            retries:        self.retries.and_then(|r| i64::try_from(r).ok()),
            start_period:   self.start_period_ms.map(ms_to_ns),
            start_interval: None,
        }
    }
}

/// The container name of `sidecar` on `network`.
fn container_name(network: &str, sidecar: &Sidecar) -> String {
    format!("{network}-{}", sidecar.name)
}

/// Creates the network and every sidecar on it, then waits for the ones
/// with a health check to report healthy. Tears down what it started on
/// any failure.
pub(crate) async fn realize(docker: &Docker, network: &str, sidecars: &[Sidecar]) -> Result<()> {
    let mut labels = HashMap::new();
    labels.insert(MANAGED_LABEL.to_owned(), "true".to_owned());
    labels.insert(NETWORK_LABEL.to_owned(), network.to_owned());
    docker
        .create_network(CreateNetworkOptions {
            name: network.to_owned(),
            labels: labels.clone(),
            ..Default::default()
        })
        .await
        .map_err(|error| docker_error("creating sidecar network", error))?;

    match start_all(docker, network, sidecars, &labels).await {
        Ok(()) => Ok(()),
        Err(error) => {
            sweep(docker, network).await;
            Err(error)
        }
    }
}

async fn start_all(
    docker: &Docker,
    network: &str,
    sidecars: &[Sidecar],
    labels: &HashMap<String, String>,
) -> Result<()> {
    for sidecar in sidecars {
        if !image_present(docker, &sidecar.image).await? {
            pull_image(docker, &sidecar.image, sidecar.registry_auth.as_ref(), None).await?;
        }
        let container = container_name(network, sidecar);
        let env: Vec<String> = sidecar
            .env
            .iter()
            .map(|(key, value)| format!("{key}={value}"))
            .collect();
        let endpoint = EndpointSettings {
            aliases: Some(vec![sidecar.name.clone()]),
            ..Default::default()
        };
        let mut endpoints = HashMap::new();
        endpoints.insert(network.to_owned(), endpoint);
        let host_config = HostConfig {
            network_mode: Some(network.to_owned()),
            dns: non_empty(sidecar.dns.clone()),
            cap_add: non_empty(sidecar.cap_add.clone()),
            ..Default::default()
        };
        let config = Config {
            image: Some(sidecar.image.clone()),
            env: non_empty(env),
            user: sidecar.user.clone(),
            entrypoint: sidecar.entrypoint.clone(),
            labels: Some(labels.clone()),
            healthcheck: sidecar.health.as_ref().map(Health::to_config),
            host_config: Some(host_config),
            networking_config: Some(NetworkingConfig {
                endpoints_config: endpoints,
            }),
            ..Default::default()
        };
        docker
            .create_container(
                Some(CreateContainerOptions {
                    name:     container.clone(),
                    platform: None,
                }),
                config,
            )
            .await
            .map_err(|error| docker_error("creating sidecar", error))?;
        docker
            .start_container(&container, None::<StartContainerOptions<String>>)
            .await
            .map_err(|error| docker_error("starting sidecar", error))?;
    }
    for sidecar in sidecars {
        if sidecar.health.is_some() {
            await_health(docker, &container_name(network, sidecar)).await?;
        }
    }
    Ok(())
}

async fn await_health(docker: &Docker, container: &str) -> Result<()> {
    let deadline = Instant::now() + HEALTH_WAIT;
    loop {
        let inspect = docker
            .inspect_container(container, None)
            .await
            .map_err(|error| docker_error("inspecting sidecar health", error))?;
        let state = inspect.state.as_ref();
        let status = state.and_then(|s| s.status);
        let health = state.and_then(|s| s.health.as_ref()).and_then(|h| h.status);
        match (status, health) {
            (_, Some(HealthStatusEnum::HEALTHY)) => return Ok(()),
            (_, Some(HealthStatusEnum::UNHEALTHY)) => {
                return Err(Error::Provider(ProviderError::new(
                    docker_kind(),
                    format!("sidecar {container} reported unhealthy"),
                )));
            }
            (Some(ContainerStateStatusEnum::EXITED | ContainerStateStatusEnum::DEAD), _) => {
                return Err(Error::Provider(ProviderError::new(
                    docker_kind(),
                    format!("sidecar {container} exited before it was healthy"),
                )));
            }
            _ => {}
        }
        if Instant::now() >= deadline {
            return Err(Error::Provider(ProviderError::new(
                docker_kind(),
                format!("sidecar {container} never reported healthy"),
            )));
        }
        time::sleep(HEALTH_POLL).await;
    }
}

fn network_filter(network: &str) -> ListContainersOptions<String> {
    let mut filters = HashMap::new();
    filters.insert("label".to_owned(), vec![format!(
        "{NETWORK_LABEL}={network}"
    )]);
    ListContainersOptions {
        all: true,
        filters,
        ..Default::default()
    }
}

/// Removes every sidecar on the network, then the network. Best-effort:
/// a missing container or network is not an error.
pub(crate) async fn sweep(docker: &Docker, network: &str) {
    if let Ok(containers) = docker.list_containers(Some(network_filter(network))).await {
        for container in containers {
            if let Some(id) = container.id {
                let _ = docker
                    .remove_container(
                        &id,
                        Some(RemoveContainerOptions {
                            force: true,
                            ..Default::default()
                        }),
                    )
                    .await;
            }
        }
    }
    let _ = docker.remove_network(network).await;
}

/// Stops or starts every sidecar on the network, alongside the main
/// container's own stop/start.
pub(crate) async fn set_running(docker: &Docker, network: &str, running: bool) -> Result<()> {
    let containers = docker
        .list_containers(Some(network_filter(network)))
        .await
        .map_err(|error| docker_error("listing sidecars", error))?;
    for container in containers {
        let Some(id) = container.id else { continue };
        if running {
            match docker
                .start_container(&id, None::<StartContainerOptions<String>>)
                .await
            {
                Ok(()) => {}
                Err(error) if is_not_found(&error) => {}
                Err(error) => return Err(docker_error("starting sidecar", error)),
            }
        } else {
            tolerate_not_modified(
                docker
                    .stop_container(&id, Some(StopContainerOptions { t: 1 }))
                    .await,
                "stopping sidecar",
            )?;
        }
    }
    Ok(())
}
