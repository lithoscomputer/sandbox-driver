use std::collections::BTreeMap;
use std::fmt;
use std::num::{NonZeroU16, NonZeroU32, NonZeroU64};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::Error;
use crate::{SnapshotId, WorkspaceOwnership};

/// The caller's workload, never a helper image or outer runner.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Source {
    Image(String),
    Dockerfile(String),
    Snapshot(SnapshotId),
    /// No image. Workspace path/ownership are carried by the spec.
    HostDirectory,
}

/// Normalized resource requests. Memory/disk are MiB; CPU is whole cores.
/// Human-readable size parsing belongs to the future catalog, not providers.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Resources {
    pub cpu_cores: Option<NonZeroU32>,
    pub memory_mb: Option<NonZeroU64>,
    pub disk_mb:   Option<NonZeroU64>,
    pub gpus:      Option<u32>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub enum NetworkPolicy {
    #[default]
    ProviderDefault,
    AllowAll,
    Block,
    CidrAllowList {
        cidrs: Vec<String>,
    },
    DomainAllowList {
        domains: Vec<String>,
    },
}

/// Backend timers, in milliseconds. None inherits a provider default; zero
/// explicitly disables the timer. Application run-end policy is not a timer.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Timers {
    pub auto_stop_ms:    Option<u64>,
    pub auto_archive_ms: Option<u64>,
    pub auto_delete_ms:  Option<u64>,
    pub ttl_ms:          Option<u64>,
}

/// Portable workload declaration. This unvalidated DTO is deliberately
/// separate from `crate::SandboxSpec`: legacy providers must not silently
/// ignore services, container options, or the new workload-target semantics.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxSpec {
    pub source:              Source,
    #[serde(default)]
    pub name:                Option<String>,
    #[serde(default)]
    pub resources:           Resources,
    #[serde(default)]
    pub network:             NetworkPolicy,
    #[serde(default)]
    pub timers:              Timers,
    #[serde(default)]
    pub labels:              BTreeMap<String, String>,
    #[serde(default)]
    pub env:                 BTreeMap<String, String>,
    #[serde(default)]
    pub working_directory:   Option<String>,
    #[serde(default)]
    pub workspace_ownership: Option<WorkspaceOwnership>,
    #[serde(default)]
    pub user:                Option<String>,
    #[serde(default)]
    pub services:            BTreeMap<String, ServiceSpec>,
    #[serde(default)]
    pub container:           Option<ContainerSpec>,
    #[serde(default)]
    pub provider_config:     BTreeMap<String, Value>,
}

impl SandboxSpec {
    pub fn new(source: Source) -> Self {
        Self {
            source,
            name: None,
            resources: Resources::default(),
            network: NetworkPolicy::default(),
            timers: Timers::default(),
            labels: BTreeMap::new(),
            env: BTreeMap::new(),
            working_directory: None,
            workspace_ownership: None,
            user: None,
            services: BTreeMap::new(),
            container: None,
            provider_config: BTreeMap::new(),
        }
    }

    /// Checks portable invariants only. Descriptor capabilities, provider
    /// schemas, credentials, and backend-specific restrictions still need
    /// validation before admission; a successful check does not start work.
    pub fn validate(&self) -> Result<(), Error> {
        match &self.source {
            Source::Image(value) | Source::Dockerfile(value) if value.trim().is_empty() => {
                return Err(Error::invalid_spec("source", "must not be empty"));
            }
            _ => {}
        }
        if self.working_directory.as_deref() == Some("") {
            return Err(Error::invalid_spec(
                "working_directory",
                "must not be empty",
            ));
        }
        if self.workspace_ownership.is_some() && self.source != Source::HostDirectory {
            return Err(Error::invalid_spec(
                "workspace_ownership",
                "requires host_directory",
            ));
        }
        if self.workspace_ownership == Some(WorkspaceOwnership::Designated)
            && self.working_directory.is_none()
        {
            return Err(Error::invalid_spec(
                "working_directory",
                "designated workspace requires a path",
            ));
        }
        match &self.network {
            NetworkPolicy::CidrAllowList { cidrs } if cidrs.is_empty() => {
                return Err(Error::invalid_spec("network.cidrs", "must not be empty"));
            }
            NetworkPolicy::DomainAllowList { domains } if domains.is_empty() => {
                return Err(Error::invalid_spec("network.domains", "must not be empty"));
            }
            _ => {}
        }
        for (name, service) in &self.services {
            if name.is_empty()
                || !name
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                || name.starts_with('-')
                || name.ends_with('-')
                || name.len() > 63
            {
                return Err(Error::invalid_spec(
                    "services",
                    "service names must be lowercase DNS labels of at most 63 bytes",
                ));
            }
            service.validate().map_err(|error| match error {
                Error::InvalidSpec { path, message } => {
                    Error::invalid_spec(format!("services.{name}.{path}"), message)
                }
                other => other,
            })?;
        }
        Ok(())
    }
}

impl fmt::Debug for SandboxSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SandboxSpec")
            .field("source", &"<redacted>")
            .field("env", &"<redacted>")
            .field("services", &self.services)
            .field("provider_config", &"<redacted>")
            .finish_non_exhaustive()
    }
}

/// A sibling service container. Credentials are names resolved by the driver,
/// not registry passwords. Readiness commands execute *inside this service*.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceSpec {
    pub image:      String,
    #[serde(default)]
    pub env:        BTreeMap<String, String>,
    /// TCP ports to make reachable from the workload; not host-public mappings.
    #[serde(default)]
    pub ports:      Vec<NonZeroU16>,
    #[serde(default)]
    pub credential: Option<String>,
    #[serde(default)]
    pub ready:      Option<ReadinessCheck>,
}

impl ServiceSpec {
    pub fn new(image: impl Into<String>) -> Self {
        Self {
            image:      image.into(),
            env:        BTreeMap::new(),
            ports:      Vec::new(),
            credential: None,
            ready:      None,
        }
    }

    fn validate(&self) -> Result<(), Error> {
        if self.image.trim().is_empty() {
            return Err(Error::invalid_spec("image", "must not be empty"));
        }
        if self.credential.as_deref() == Some("") {
            return Err(Error::invalid_spec("credential", "must not be empty"));
        }
        if let Some(ready) = &self.ready {
            ready.validate()?;
        }
        Ok(())
    }
}

impl fmt::Debug for ServiceSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServiceSpec")
            .field("image", &self.image)
            .field("env", &"<redacted>")
            .field("ports", &self.ports)
            .field("credential", &self.credential)
            .field("ready", &self.ready)
            .finish()
    }
}

/// Finite readiness budget. `timeout_ms` caps each attempt, `deadline_ms` caps
/// all attempts and waits, and `retries` is the maximum number of attempts.
/// A zero exit code passes; timeout/nonzero fails that attempt. No shell is
/// implied. Absence of a check requires only that the service has started.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadinessCheck {
    pub command:     Vec<String>,
    pub interval_ms: NonZeroU64,
    pub timeout_ms:  NonZeroU64,
    pub deadline_ms: NonZeroU64,
    pub retries:     NonZeroU32,
}

impl ReadinessCheck {
    fn validate(&self) -> Result<(), Error> {
        if self.command.first().is_none_or(String::is_empty) {
            return Err(Error::invalid_spec(
                "ready.command",
                "requires a non-empty executable",
            ));
        }
        if self.command.iter().any(|arg| arg.contains('\0')) {
            return Err(Error::invalid_spec(
                "ready.command",
                "arguments must not contain NUL",
            ));
        }
        Ok(())
    }
}

impl fmt::Debug for ReadinessCheck {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReadinessCheck")
            .field("command", &"<redacted>")
            .field("interval_ms", &self.interval_ms)
            .field("timeout_ms", &self.timeout_ms)
            .field("deadline_ms", &self.deadline_ms)
            .field("retries", &self.retries)
            .finish()
    }
}

/// Requests about the workload container, never instructions for an outer
/// runner. None leaves an option unspecified; Some(false) explicitly disables
/// it and must not be silently ignored on an unsupported provider.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ContainerSpec {
    pub init:              Option<bool>,
    pub privileged:        Option<bool>,
    pub capabilities_add:  Vec<String>,
    pub capabilities_drop: Vec<String>,
    pub dns:               Vec<String>,
    pub extra_hosts:       BTreeMap<String, String>,
    pub shm_size_mb:       Option<NonZeroU64>,
}
