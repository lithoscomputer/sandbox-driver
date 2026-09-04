//! The Docker provider's `provider_config` types come from
//! `sandbox-driver-docker-config`, so a host over the plugin wire can
//! build them without this crate. What lives here is the one direction the
//! provider needs: the Serde types mapped onto Bollard's request shapes.

use bollard::auth::DockerCredentials;
use bollard::models::HealthConfig;
pub use sandbox_driver_docker_config::{
    BindMount, DockerProviderConfig, Health, RegistryAuth, Sidecar,
};

pub(crate) fn to_credentials(auth: &RegistryAuth) -> DockerCredentials {
    DockerCredentials {
        username: Some(auth.username.clone()),
        password: Some(auth.password.clone()),
        serveraddress: auth.server.clone(),
        ..Default::default()
    }
}

pub(crate) fn to_health_config(health: &Health) -> HealthConfig {
    HealthConfig {
        test:           Some(vec!["CMD-SHELL".to_owned(), health.cmd.clone()]),
        interval:       health.interval_ms.map(ms_to_ns),
        timeout:        health.timeout_ms.map(ms_to_ns),
        retries:        health.retries.and_then(|r| i64::try_from(r).ok()),
        start_period:   health.start_period_ms.map(ms_to_ns),
        start_interval: None,
    }
}

fn ms_to_ns(ms: u64) -> i64 {
    i64::try_from(ms.saturating_mul(1_000_000)).unwrap_or(i64::MAX)
}
