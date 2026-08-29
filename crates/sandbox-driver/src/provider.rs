use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::SystemTime;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::capabilities::{Capabilities, Capability};
use crate::error::{Error, Result};
use crate::event::EventCallback;
use crate::id::{ProviderKind, SandboxId, SnapshotId, VolumeId};
use crate::logs::LogSink;
use crate::sandbox::Sandbox;
use crate::spec::{Resources, SandboxSpec};
use crate::state::SandboxStatus;

/// A sandbox backend: host, docker, daytona, or a JSON-RPC plugin.
///
/// `create` provisions **and** returns the handle — there is no separate
/// build step. `attach` re-attaches to an existing sandbox by the ID the
/// caller persisted.
#[async_trait]
pub trait SandboxProvider: Send + Sync {
    fn kind(&self) -> &ProviderKind;

    /// The provider's capability upper bound (union over sandbox classes),
    /// for pre-create decisions. The per-sandbox set is authoritative.
    fn capabilities(&self) -> &Capabilities;

    /// Provisions a sandbox and returns its handle. The event callback is
    /// scoped to the returned handle's lifetime.
    async fn create(
        &self,
        spec: &SandboxSpec,
        events: Option<EventCallback>,
    ) -> Result<Arc<dyn Sandbox>>;

    /// Re-attaches to an existing sandbox by persisted ID.
    async fn attach(
        &self,
        id: &SandboxId,
        events: Option<EventCallback>,
    ) -> Result<Arc<dyn Sandbox>>;

    /// Lists sandboxes this provider manages. Providers that cannot
    /// enumerate declare it via capabilities and return an empty list.
    async fn list(&self, filter: &SandboxFilter) -> Result<Vec<SandboxStatus>>;

    /// Snapshot management, when the provider has it.
    fn snapshots(&self) -> Option<&dyn SnapshotProvider> {
        None
    }

    /// Volume management, when the provider has it.
    fn volumes(&self) -> Option<&dyn VolumeProvider> {
        None
    }
}

/// Filter for [`SandboxProvider::list`].
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[non_exhaustive]
pub struct SandboxFilter {
    /// Labels the sandbox must carry (all of them).
    pub labels: BTreeMap<String, String>,
}

/// Snapshot management for one provider.
#[async_trait]
pub trait SnapshotProvider: Send + Sync {
    /// Starts creating a snapshot; poll [`SnapshotProvider::get`] or follow
    /// [`SnapshotProvider::build_logs`] for progress.
    async fn create(&self, spec: &SnapshotSpec) -> Result<SnapshotId>;

    async fn get(&self, id: &SnapshotId) -> Result<SnapshotStatus>;

    async fn list(&self, filter: &SnapshotFilter) -> Result<Vec<SnapshotStatus>>;

    /// Idempotent delete.
    async fn delete(&self, id: &SnapshotId) -> Result<()>;

    /// Streams snapshot build output. Capability-gated on
    /// `snapshots.build_logs`.
    async fn build_logs(&self, id: &SnapshotId, follow: bool, sink: LogSink) -> Result<()> {
        let _ = (id, follow, sink);
        Err(Error::unsupported(Capability::Snapshots))
    }
}

/// What a snapshot is built from.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum SnapshotSource {
    Image {
        reference: String,
    },
    Dockerfile {
        content: String,
    },
    /// Snapshot a live sandbox, optionally including VM memory.
    Sandbox {
        id:             SandboxId,
        include_memory: bool,
    },
}

/// Creation request for [`SnapshotProvider::create`].
#[derive(Clone, Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub struct SnapshotSpec {
    pub name:            Option<String>,
    pub source:          SnapshotSource,
    pub resources:       Resources,
    /// Provider-specific options.
    pub provider_config: serde_json::Value,
}

impl SnapshotSpec {
    pub fn new(source: SnapshotSource) -> Self {
        Self {
            name: None,
            source,
            resources: Resources::default(),
            provider_config: serde_json::Value::Null,
        }
    }
}

/// Snapshot lifecycle state.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum SnapshotState {
    Building,
    Active,
    Inactive,
    Error,
    Deleting,
    #[serde(other)]
    Unknown,
}

/// Observed snapshot status.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub struct SnapshotStatus {
    pub id:           SnapshotId,
    pub name:         Option<String>,
    pub state:        SnapshotState,
    pub error_reason: Option<String>,
    pub size_bytes:   Option<u64>,
    pub created_at:   Option<SystemTime>,
}

impl SnapshotStatus {
    pub fn new(id: SnapshotId, state: SnapshotState) -> Self {
        Self {
            id,
            name: None,
            state,
            error_reason: None,
            size_bytes: None,
            created_at: None,
        }
    }
}

/// Filter for [`SnapshotProvider::list`].
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[non_exhaustive]
pub struct SnapshotFilter {
    pub name: Option<String>,
}

/// Volume management for one provider. Volumes attach to sandboxes at
/// create time only, via [`crate::VolumeMount`].
#[async_trait]
pub trait VolumeProvider: Send + Sync {
    async fn create(&self, spec: &VolumeSpec) -> Result<VolumeId>;

    async fn get(&self, id: &VolumeId) -> Result<VolumeStatus>;

    async fn list(&self) -> Result<Vec<VolumeStatus>>;

    /// Idempotent delete.
    async fn delete(&self, id: &VolumeId) -> Result<()>;
}

/// Creation request for [`VolumeProvider::create`].
#[derive(Clone, Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub struct VolumeSpec {
    pub name:    String,
    /// Requested size; elastic providers (Daytona) ignore it.
    pub size_mb: Option<u64>,
}

impl VolumeSpec {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name:    name.into(),
            size_mb: None,
        }
    }
}

/// Volume lifecycle state.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum VolumeState {
    Creating,
    Ready,
    Deleting,
    Deleted,
    Error,
    #[serde(other)]
    Unknown,
}

/// Observed volume status.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub struct VolumeStatus {
    pub id:           VolumeId,
    pub name:         Option<String>,
    pub state:        VolumeState,
    pub error_reason: Option<String>,
    pub created_at:   Option<SystemTime>,
}

impl VolumeStatus {
    pub fn new(id: VolumeId, state: VolumeState) -> Self {
        Self {
            id,
            name: None,
            state,
            error_reason: None,
            created_at: None,
        }
    }
}
