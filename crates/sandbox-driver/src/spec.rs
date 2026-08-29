use std::collections::BTreeMap;
use std::time::Duration;

use serde::{Deserialize, Serialize};

/// What a sandbox is created from.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum SandboxSource {
    /// An OCI image reference, e.g. `"ubuntu:24.04"`.
    Image { reference: String },
    /// A Dockerfile to build. Build context handling is provider-specific.
    Dockerfile { content: String },
    /// An existing snapshot, by provider id or name.
    Snapshot { name: String },
    /// Host provider: no image at all, just a working directory.
    HostDirectory,
}

/// Requested compute resources. Units are explicit in the field names;
/// `None` means provider default.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Resources {
    pub cpu_cores: Option<u32>,
    pub memory_mb: Option<u64>,
    pub disk_mb:   Option<u64>,
    pub gpus:      Option<u32>,
}

/// Network policy for a sandbox.
///
/// The default is the provider's own default (Docker: bridge; Daytona:
/// allow-all) — a closed sandbox requires an explicit `Block`.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum NetworkPolicy {
    #[default]
    ProviderDefault,
    AllowAll,
    Block,
    /// Outbound restricted to these CIDRs.
    CidrAllowList {
        cidrs: Vec<String>,
    },
    /// Outbound restricted to these domains.
    DomainAllowList {
        domains: Vec<String>,
    },
}

/// A volume attached at sandbox create time (the only attach point —
/// no provider in scope supports runtime attach).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub struct VolumeMount {
    /// Volume id or name; resolved by the provider.
    pub volume:     String,
    pub mount_path: String,
    pub subpath:    Option<String>,
}

impl VolumeMount {
    pub fn new(volume: impl Into<String>, mount_path: impl Into<String>) -> Self {
        Self {
            volume:     volume.into(),
            mount_path: mount_path.into(),
            subpath:    None,
        }
    }
}

/// Idle and lifetime timers. `None` leaves the provider default in place.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct LifecycleTimers {
    pub auto_stop_after_idle:    Option<Duration>,
    /// Mutually exclusive with `auto_stop_after_idle` on providers that
    /// distinguish pause from stop.
    pub auto_pause_after_idle:   Option<Duration>,
    pub auto_archive_after_stop: Option<Duration>,
    pub auto_delete_after_stop:  Option<Duration>,
    /// Wall-clock lifetime since creation, regardless of state.
    pub ttl:                     Option<Duration>,
}

/// Platform details of a running sandbox.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub struct PlatformInfo {
    /// Operating system, e.g. `"linux"`.
    pub os:      String,
    /// CPU architecture, e.g. `"aarch64"`.
    pub arch:    String,
    /// Free-form version string, e.g. a kernel release.
    pub version: String,
}

impl PlatformInfo {
    pub fn new(os: impl Into<String>, arch: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            os:      os.into(),
            arch:    arch.into(),
            version: version.into(),
        }
    }
}

/// Provisioning request for [`crate::SandboxProvider::create`].
///
/// This is deliberately an **unvalidated wire DTO**: fields are public so
/// it round-trips the JSON-RPC boundary, and it can express combinations
/// no provider accepts. Validation happens at the provider boundary —
/// every provider calls [`SandboxSpec::validate`] for the cross-provider
/// invariants and adds its own provider-specific checks, returning
/// [`crate::Error::InvalidSpec`].
///
/// Construct with [`SandboxSpec::new`] and refine with the consuming
/// setters. `provider_config` is the typed escape hatch for
/// provider-specific options (GPU preference lists, spot instances, warm
/// pools, …); it crosses the JSON-RPC boundary opaquely.
///
/// Deliberately absent: clone URLs, branches, credentials. Repository
/// cloning is an orchestration recipe over `Exec`/`Git`, not a
/// provisioning concern.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub struct SandboxSpec {
    pub name:              Option<String>,
    pub source:            SandboxSource,
    pub resources:         Resources,
    pub env:               BTreeMap<String, String>,
    pub labels:            BTreeMap<String, String>,
    pub user:              Option<String>,
    /// For the Host provider: `Some(path)` designates a caller-owned
    /// directory that `delete` must never remove; `None` asks for a
    /// managed temporary workspace.
    pub working_directory: Option<String>,
    pub network:           NetworkPolicy,
    pub volumes:           Vec<VolumeMount>,
    pub timers:            LifecycleTimers,
    /// First-class ephemeral flag; providers translate to their encoding
    /// (Daytona: `auto_delete_interval == 0`).
    pub ephemeral:         bool,
    pub public:            Option<bool>,
    pub region:            Option<String>,
    /// Provider-specific options, documented by each provider's schema.
    pub provider_config:   serde_json::Value,
}

impl SandboxSpec {
    pub fn new(source: SandboxSource) -> Self {
        Self {
            name: None,
            source,
            resources: Resources::default(),
            env: BTreeMap::new(),
            labels: BTreeMap::new(),
            user: None,
            working_directory: None,
            network: NetworkPolicy::default(),
            volumes: Vec::new(),
            timers: LifecycleTimers::default(),
            ephemeral: false,
            public: None,
            region: None,
            provider_config: serde_json::Value::Null,
        }
    }

    #[must_use]
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    #[must_use]
    pub fn resources(mut self, resources: Resources) -> Self {
        self.resources = resources;
        self
    }

    #[must_use]
    pub fn env_var(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.env.insert(key.into(), value.into());
        self
    }

    #[must_use]
    pub fn label(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.labels.insert(key.into(), value.into());
        self
    }

    #[must_use]
    pub fn working_directory(mut self, path: impl Into<String>) -> Self {
        self.working_directory = Some(path.into());
        self
    }

    #[must_use]
    pub fn network(mut self, network: NetworkPolicy) -> Self {
        self.network = network;
        self
    }

    #[must_use]
    pub fn volume(mut self, mount: VolumeMount) -> Self {
        self.volumes.push(mount);
        self
    }

    #[must_use]
    pub fn timers(mut self, timers: LifecycleTimers) -> Self {
        self.timers = timers;
        self
    }

    #[must_use]
    pub fn ephemeral(mut self, ephemeral: bool) -> Self {
        self.ephemeral = ephemeral;
        self
    }

    #[must_use]
    pub fn provider_config(mut self, config: serde_json::Value) -> Self {
        self.provider_config = config;
        self
    }

    /// Checks the cross-provider invariants. Providers call this at
    /// `create` before their own provider-specific validation.
    pub fn validate(&self) -> Result<(), crate::Error> {
        if self.timers.auto_stop_after_idle.is_some() && self.timers.auto_pause_after_idle.is_some()
        {
            return Err(crate::Error::invalid_spec(
                "timers",
                "auto_stop_after_idle and auto_pause_after_idle are mutually exclusive",
            ));
        }
        if self.working_directory.as_deref() == Some("") {
            return Err(crate::Error::invalid_spec(
                "working_directory",
                "must not be empty",
            ));
        }
        for mount in &self.volumes {
            if mount.volume.is_empty() {
                return Err(crate::Error::invalid_spec(
                    "volumes",
                    "volume id must not be empty",
                ));
            }
            if !mount.mount_path.starts_with('/') {
                return Err(crate::Error::invalid_spec(
                    "volumes",
                    "mount_path must be an absolute path",
                ));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spec_builder_sets_fields() {
        let spec = SandboxSpec::new(SandboxSource::Image {
            reference: "ubuntu:24.04".into(),
        })
        .name("demo")
        .env_var("FOO", "bar")
        .ephemeral(true);
        assert_eq!(spec.name.as_deref(), Some("demo"));
        assert_eq!(spec.env.get("FOO").map(String::as_str), Some("bar"));
        assert!(spec.ephemeral);
    }

    #[test]
    fn spec_round_trips_through_json() {
        let spec = SandboxSpec::new(SandboxSource::Snapshot {
            name: "base".into(),
        });
        let json = serde_json::to_string(&spec).expect("serializes");
        let back: SandboxSpec = serde_json::from_str(&json).expect("deserializes");
        assert!(matches!(back.source, SandboxSource::Snapshot { name } if name == "base"));
    }
}
