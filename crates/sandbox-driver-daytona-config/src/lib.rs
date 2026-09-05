//! Typed Daytona `SandboxSpec::provider_config` for plugin clients.

use sandbox_driver_docker_config::DockerProviderConfig;
use serde::{Deserialize, Serialize};

/// Optional Daytona extensions. Unknown fields are rejected.
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DaytonaProviderConfig {
    /// Route outbound HTTP(S) through this proxy. May contain credentials.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outbound_proxy_url: Option<String>,
    /// Run Docker inside the sandbox. Requires `start-docker` and Python 3.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub docker:             Option<NestedDockerConfig>,
}

impl DaytonaProviderConfig {
    pub fn into_value(self) -> serde_json::Value {
        serde_json::to_value(self).expect("Daytona configuration is plain serializable data")
    }
}

/// A container owned by the Daytona sandbox. Its workspace is a bind of
/// the VM workspace; no caller filesystem paths cross the connection.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NestedDockerConfig {
    /// Job image, or a small helper image when execution stays in the VM.
    pub image:   String,
    #[serde(default)]
    pub target:  DockerExecutionTarget,
    /// User inside the container. The VM bootstrap still runs as its user.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user:    Option<String>,
    #[serde(default)]
    pub options: DockerProviderConfig,
}

/// Where ordinary exec and filesystem operations run.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DockerExecutionTarget {
    /// Ordinary operations and one-shot containers share the job container.
    #[default]
    Container,
    /// Ordinary operations stay in the VM. A helper container gives
    /// one-shots access to its workspace and host network namespace.
    VirtualMachine,
}
