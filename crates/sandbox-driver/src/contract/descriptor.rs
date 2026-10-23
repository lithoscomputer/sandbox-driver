use std::collections::{BTreeMap, BTreeSet};
use std::num::NonZeroU16;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::NamespaceId;
use crate::{Isolation, ProviderKind};

/// JSON Schema object. Validation against its dialect belongs to the catalog
/// implementation; merely deserializing this DTO does not validate a schema.
pub type JsonSchema = BTreeMap<String, Value>;

/// Credential-free metadata returned before a configured runtime is started.
/// These schemas must not require a backend connection to discover.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ProviderSchemas {
    pub kind:          ProviderKind,
    pub version:       String,
    /// Validates `ProviderEntry.config` only.
    pub config_schema: JsonSchema,
    /// Validates `SandboxSpec.provider_config`, not connection configuration.
    /// `None` means opaque provider validation, not permission to drop fields.
    #[serde(default)]
    pub spec_schema:   Option<JsonSchema>,
    /// Required credential names; values never appear in metadata.
    #[serde(default)]
    pub secrets:       Vec<String>,
}

/// Configured runtime facts. These are not available from metadata alone.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Descriptor {
    pub schemas:      ProviderSchemas,
    pub namespace:    Namespace,
    /// Security boundary of the workload, independent of its source format.
    pub isolation:    Isolation,
    pub durability:   Durability,
    pub access:       AccessScope,
    pub sources:      Vec<SourceKind>,
    pub locality:     Locality,
    pub resources:    Vec<ResourceCapability>,
    pub network:      Vec<NetworkMode>,
    pub ports:        PortSupport,
    pub capabilities: CapabilitySet,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Namespace {
    pub id:    NamespaceId,
    pub scope: NamespaceScope,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NamespaceScope {
    Process,
    Machine,
    Remote,
}

/// Resource survival, independent of whether another instance can access it.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Durability {
    Process,
    Machine,
    Remote,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessScope {
    /// Only the owning live provider instance can operate the sandbox.
    OwnerProcess,
    /// Instances reaching the same namespace coordinate a common stop fence.
    Shared,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceKind {
    HostDirectory,
    Image,
    Dockerfile,
    Snapshot,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct Locality {
    /// Address reachable from the workload, if any; never an outer-runner
    /// target.
    pub host_address:      Option<String>,
    #[serde(default)]
    pub mounts_host_paths: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceCapability {
    Cpu,
    Memory,
    Disk,
    Gpus,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkMode {
    ProviderDefault,
    AllowAll,
    Block,
    CidrAllowList,
    DomainAllowList,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "exposable", content = "ports", rename_all = "snake_case")]
pub enum PortSupport {
    #[default]
    None,
    Any,
    /// Workload port numbers.
    Selected(BTreeSet<NonZeroU16>),
}

/// Optional features are absent unless explicitly advertised. Services are a
/// spec capability, not the legacy background-process Services facet.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct CapabilitySet {
    pub lifecycle:        Vec<LifecycleCapability>,
    pub endpoints:        Vec<EndpointCapability>,
    pub services:         bool,
    /// One-shot containers in the workload's workspace/network.
    pub containers:       bool,
    /// Supported workload container options, independent of service support.
    pub container_fields: Vec<ContainerField>,
    /// Timers the provider enforces. A request for any other timer is
    /// `Unsupported`, never silently ignored.
    pub timers:           Vec<TimerCapability>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleCapability {
    Pause,
    Resume,
    Archive,
    Recover,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EndpointCapability {
    Ssh,
    ShellCommand,
    Vnc,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContainerField {
    Init,
    Privileged,
    CapabilitiesAdd,
    CapabilitiesDrop,
    Dns,
    ExtraHosts,
    ShmSizeMb,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TimerCapability {
    AutoStop,
    AutoArchive,
    AutoDelete,
    Ttl,
}
