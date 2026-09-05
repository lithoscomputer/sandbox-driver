use std::collections::BTreeMap;
use std::fmt;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::SnapshotId;

/// Provisioning form of a sandbox.
///
/// This is distinct from [`crate::Isolation`]: a provider can implement a
/// container sandbox with a VM-backed security boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum SandboxKind {
    Container,
    VirtualMachine,
    /// A kind sent by a newer protocol peer.
    #[serde(other)]
    Unknown,
}

/// What a sandbox is created from.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum SandboxSource {
    /// An OCI image reference, e.g. `"ubuntu:24.04"`.
    Image { reference: String },
    /// A Dockerfile to build. Build context handling is provider-specific.
    Dockerfile { content: String },
    /// An existing snapshot, by provider-scoped id or name.
    Snapshot { id: SnapshotId },
    /// Host provider: no image at all, just a working directory.
    HostDirectory,
}

/// Requested compute resources. Units are explicit in the field names;
/// `None` means provider default.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(default)]
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

impl NetworkPolicy {
    /// Checks the policy's own invariants. An empty allow-list is
    /// rejected rather than passed through: providers treat a present
    /// but empty allow-list as no restriction at all (Daytona: open
    /// egress), the opposite of what an emptied-out filter intends.
    pub fn validate(&self) -> Result<(), crate::Error> {
        match self {
            Self::CidrAllowList { cidrs } if cidrs.is_empty() => Err(crate::Error::invalid_spec(
                "network",
                "cidr allow-list must not be empty",
            )),
            Self::DomainAllowList { domains } if domains.is_empty() => Err(
                crate::Error::invalid_spec("network", "domain allow-list must not be empty"),
            ),
            _ => Ok(()),
        }
    }
}

/// A volume attached at sandbox create time, the portable attach point.
/// Provider-specific runtime attachment remains outside this interface.
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

/// Idle and lifetime timers. `None` leaves the provider default in
/// place; `Duration::ZERO` is the explicit "never".
///
/// Provider defaults can be short: Daytona auto-stops after **15 idle
/// minutes**, less than a single long build or inference call. A
/// caller running long commands sets `auto_stop_after_idle` explicitly
/// rather than inheriting that default (fabro uses 120 minutes).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(default)]
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
#[derive(Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct SandboxSpec {
    #[serde(default)]
    pub name:                Option<String>,
    pub source:              SandboxSource,
    #[serde(default)]
    pub resources:           Resources,
    /// Required provisioning kind for the resulting sandbox. Providers
    /// must honor it or reject the request; they must not silently change
    /// the kind or create hidden intermediate snapshots.
    #[serde(default)]
    pub sandbox_kind:        Option<SandboxKind>,
    #[serde(default)]
    pub env:                 BTreeMap<String, String>,
    #[serde(default)]
    pub labels:              BTreeMap<String, String>,
    #[serde(default)]
    pub user:                Option<String>,
    /// The workspace directory commands use by default. Providers create
    /// it when needed and preserve it when a sandbox is attached again.
    /// For the Host provider, `Some(path)` designates a caller-owned
    /// directory that `delete` must never remove; `None` asks for a
    /// managed temporary workspace.
    #[serde(default)]
    pub working_directory:   Option<String>,
    /// Host only. A named directory is designated by default. Setting
    /// `Managed` explicitly transfers its creation and deletion to Host.
    #[serde(default)]
    pub workspace_ownership: Option<crate::WorkspaceOwnership>,
    #[serde(default)]
    pub network:             NetworkPolicy,
    #[serde(default)]
    pub volumes:             Vec<VolumeMount>,
    #[serde(default)]
    pub timers:              LifecycleTimers,
    /// First-class ephemeral flag; providers translate to their encoding
    /// (Daytona: `auto_delete_interval == 0`).
    #[serde(default)]
    pub ephemeral:           bool,
    #[serde(default)]
    pub public:              Option<bool>,
    #[serde(default)]
    pub region:              Option<String>,
    /// Provider-specific options, documented by each provider's schema.
    #[serde(default)]
    pub provider_config:     serde_json::Value,
}

// The env map is the designated secret channel and provider_config can
// carry credentials (proxy URLs); `Debug` redacts both so tracing a
// spec can never leak them.
impl fmt::Debug for SandboxSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SandboxSpec")
            .field("name", &self.name)
            .field("source", &self.source)
            .field("resources", &self.resources)
            .field("sandbox_kind", &self.sandbox_kind)
            .field("env_keys", &self.env.keys().collect::<Vec<_>>())
            .field("labels", &self.labels)
            .field("user", &self.user)
            .field("working_directory", &self.working_directory)
            .field("workspace_ownership", &self.workspace_ownership)
            .field("network", &self.network)
            .field("volumes", &self.volumes)
            .field("timers", &self.timers)
            .field("ephemeral", &self.ephemeral)
            .field("public", &self.public)
            .field("region", &self.region)
            .field("provider_config", &"<redacted>")
            .finish()
    }
}

impl SandboxSpec {
    pub fn new(source: SandboxSource) -> Self {
        Self {
            name: None,
            source,
            resources: Resources::default(),
            sandbox_kind: None,
            env: BTreeMap::new(),
            labels: BTreeMap::new(),
            user: None,
            working_directory: None,
            workspace_ownership: None,
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
    pub fn sandbox_kind(mut self, sandbox_kind: SandboxKind) -> Self {
        self.sandbox_kind = Some(sandbox_kind);
        self
    }

    #[must_use]
    pub fn region(mut self, region: impl Into<String>) -> Self {
        self.region = Some(region.into());
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
        if self.workspace_ownership.is_some()
            && !matches!(self.source, SandboxSource::HostDirectory)
        {
            return Err(crate::Error::invalid_spec(
                "workspace_ownership",
                "only a host directory has explicit workspace ownership",
            ));
        }
        if self.workspace_ownership == Some(crate::WorkspaceOwnership::Designated)
            && self.working_directory.is_none()
        {
            return Err(crate::Error::invalid_spec(
                "working_directory",
                "a designated workspace needs a directory",
            ));
        }
        if self.sandbox_kind == Some(SandboxKind::Unknown) {
            return Err(crate::Error::invalid_spec(
                "sandbox_kind",
                "unknown sandbox kind",
            ));
        }
        if self.region.as_deref() == Some("") {
            return Err(crate::Error::invalid_spec("region", "must not be empty"));
        }
        self.network.validate()?;
        if self
            .timers
            .auto_stop_after_idle
            .is_some_and(|value| !value.is_zero())
            && self
                .timers
                .auto_pause_after_idle
                .is_some_and(|value| !value.is_zero())
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
    fn disabled_idle_timers_can_be_set_together_or_beside_one_enabled_timer() {
        for stop in [None, Some(Duration::ZERO), Some(Duration::from_secs(60))] {
            for pause in [None, Some(Duration::ZERO), Some(Duration::from_secs(60))] {
                let mut spec = SandboxSpec::new(SandboxSource::HostDirectory);
                spec.timers.auto_stop_after_idle = stop;
                spec.timers.auto_pause_after_idle = pause;
                let both_enabled = stop.is_some_and(|value| !value.is_zero())
                    && pause.is_some_and(|value| !value.is_zero());
                assert_eq!(
                    spec.validate().is_err(),
                    both_enabled,
                    "stop={stop:?}, pause={pause:?}"
                );
            }
        }
    }

    #[test]
    fn spec_builder_sets_fields() {
        let spec = SandboxSpec::new(SandboxSource::Image {
            reference: "ubuntu:24.04".into(),
        })
        .name("demo")
        .sandbox_kind(SandboxKind::Container)
        .region("us")
        .env_var("FOO", "bar")
        .ephemeral(true);
        assert_eq!(spec.name.as_deref(), Some("demo"));
        assert_eq!(spec.sandbox_kind, Some(SandboxKind::Container));
        assert_eq!(spec.region.as_deref(), Some("us"));
        assert_eq!(spec.env.get("FOO").map(String::as_str), Some("bar"));
        assert!(spec.ephemeral);
    }

    #[test]
    fn spec_round_trips_through_json() {
        let spec = SandboxSpec::new(SandboxSource::Snapshot {
            id: SnapshotId::try_new("base").expect("valid snapshot id"),
        });
        let json = serde_json::to_string(&spec).expect("serializes");
        let back: SandboxSpec = serde_json::from_str(&json).expect("deserializes");
        assert!(matches!(back.source, SandboxSource::Snapshot { id } if id.as_str() == "base"));
    }

    #[test]
    fn sandbox_kind_has_stable_wire_names() {
        assert_eq!(
            serde_json::to_string(&SandboxKind::VirtualMachine).expect("serializes"),
            "\"virtual_machine\""
        );
    }

    #[test]
    fn spec_rejects_unknown_kind_and_empty_region() {
        let unknown =
            SandboxSpec::new(SandboxSource::HostDirectory).sandbox_kind(SandboxKind::Unknown);
        assert!(matches!(
            unknown.validate(),
            Err(crate::Error::InvalidSpec { .. })
        ));

        let empty_region = SandboxSpec::new(SandboxSource::HostDirectory).region("");
        assert!(matches!(
            empty_region.validate(),
            Err(crate::Error::InvalidSpec { .. })
        ));
    }

    #[test]
    fn spec_debug_redacts_env_values_and_provider_config() {
        let spec = SandboxSpec::new(SandboxSource::HostDirectory)
            .env_var("API_TOKEN", "hunter2")
            .provider_config(serde_json::json!({"proxy": "https://u:hunter2@proxy"}));
        let debug = format!("{spec:?}");
        assert!(!debug.contains("hunter2"), "debug: {debug}");
        // Keys stay visible for diagnostics.
        assert!(debug.contains("API_TOKEN"), "debug: {debug}");
    }

    #[test]
    fn spec_rejects_empty_network_allow_lists() {
        // An empty allow-list reaching a provider means "no
        // restriction", not "block everything" — it must fail closed.
        let empty_cidrs = SandboxSpec::new(SandboxSource::HostDirectory)
            .network(NetworkPolicy::CidrAllowList { cidrs: vec![] });
        assert!(matches!(
            empty_cidrs.validate(),
            Err(crate::Error::InvalidSpec { .. })
        ));

        let empty_domains = SandboxSpec::new(SandboxSource::HostDirectory)
            .network(NetworkPolicy::DomainAllowList { domains: vec![] });
        assert!(matches!(
            empty_domains.validate(),
            Err(crate::Error::InvalidSpec { .. })
        ));

        let populated =
            SandboxSpec::new(SandboxSource::HostDirectory).network(NetworkPolicy::CidrAllowList {
                cidrs: vec!["10.0.0.0/8".into()],
            });
        assert!(populated.validate().is_ok());
    }
}
