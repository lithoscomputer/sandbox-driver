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
use crate::sandbox::{Sandbox, SnapshotMode};
use crate::spec::{Resources, SandboxKind, SandboxSpec};
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

    /// Restores a recently deleted sandbox and returns a fresh handle,
    /// where the provider retains deleted sandboxes for a recovery
    /// window (Daytona: 24 hours). Provider-level because a deleted
    /// sandbox cannot be attached. Capability-gated on
    /// `lifecycle.undelete`; distinct from [`Sandbox::recover`], which
    /// repairs a live sandbox in the `Error` state.
    async fn undelete(
        &self,
        id: &SandboxId,
        events: Option<EventCallback>,
    ) -> Result<Arc<dyn Sandbox>> {
        let _ = (id, events);
        Err(Error::unsupported(Capability::LifecycleUndelete))
    }

    /// Lists sandboxes this provider manages. Providers that cannot
    /// enumerate declare it via capabilities and return an empty list.
    async fn list(&self, filter: &SandboxFilter) -> Result<Vec<SandboxStatus>>;

    /// Checks that the provider's backend is reachable and the
    /// configured credential is accepted, for preflight and diagnostics.
    ///
    /// Always callable; a provider without a real check reports
    /// [`HealthStatus::Unknown`]. `Err` is reserved for failures of the
    /// check itself, not for an unhealthy provider.
    async fn health(&self) -> Result<ProviderHealth> {
        Ok(ProviderHealth::new(HealthStatus::Unknown))
    }

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
#[serde(default)]
pub struct SandboxFilter {
    /// Labels the sandbox must carry (all of them).
    pub labels: BTreeMap<String, String>,
}

/// Outcome of a [`SandboxProvider::health`] check.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum HealthStatus {
    /// The backend is reachable and the credential is accepted.
    Ok,
    /// The backend could not be reached.
    Unreachable,
    /// The backend is reachable but rejected the credential, or the
    /// credential lacks required permissions.
    Unauthorized,
    /// The provider implements no health check.
    #[serde(other)]
    Unknown,
}

/// Report from [`SandboxProvider::health`].
#[derive(Clone, Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub struct ProviderHealth {
    pub status:              HealthStatus,
    /// Human-readable detail: which check failed and what to fix.
    #[serde(default)]
    pub message:             Option<String>,
    /// Permissions the credential is missing, when the provider can
    /// enumerate them (e.g. Daytona API key scopes).
    #[serde(default)]
    pub missing_permissions: Vec<String>,
}

impl ProviderHealth {
    pub fn new(status: HealthStatus) -> Self {
        Self {
            status,
            message: None,
            missing_permissions: Vec::new(),
        }
    }
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

    /// Reactivates an inactive snapshot so sandboxes can be created from
    /// it again (Daytona deactivates snapshots unused for two weeks).
    /// Capability-gated on `snapshots.activation`.
    async fn activate(&self, id: &SnapshotId) -> Result<()> {
        let _ = id;
        Err(Error::unsupported(Capability::SnapshotsActivation))
    }

    /// Deactivates an active snapshot, releasing whatever the provider
    /// keeps warm for it. Capability-gated on `snapshots.activation`.
    async fn deactivate(&self, id: &SnapshotId) -> Result<()> {
        let _ = id;
        Err(Error::unsupported(Capability::SnapshotsActivation))
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
    /// Snapshot a sandbox using the requested capture mode.
    Sandbox {
        id:   SandboxId,
        mode: SnapshotMode,
    },
}

/// Creation request for [`SnapshotProvider::create`].
#[derive(Clone, Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub struct SnapshotSpec {
    #[serde(default)]
    pub name:            Option<String>,
    pub source:          SnapshotSource,
    /// Kind of sandbox that can be created from this snapshot. `None`
    /// uses the provider default or inherits from a sandbox source.
    #[serde(default)]
    pub sandbox_kind:    Option<SandboxKind>,
    /// Region in which to build the snapshot.
    #[serde(default)]
    pub region:          Option<String>,
    #[serde(default)]
    pub resources:       Resources,
    /// Provider-specific options.
    #[serde(default)]
    pub provider_config: serde_json::Value,
}

impl SnapshotSpec {
    pub fn new(source: SnapshotSource) -> Self {
        Self {
            name: None,
            source,
            sandbox_kind: None,
            region: None,
            resources: Resources::default(),
            provider_config: serde_json::Value::Null,
        }
    }

    #[must_use]
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
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
    pub fn resources(mut self, resources: Resources) -> Self {
        self.resources = resources;
        self
    }

    /// Checks normalized snapshot creation invariants. Providers add
    /// their source- and kind-specific validation at the boundary.
    pub fn validate(&self) -> Result<()> {
        if self.sandbox_kind == Some(SandboxKind::Unknown) {
            return Err(Error::invalid_spec("sandbox_kind", "unknown sandbox kind"));
        }
        if self.region.as_deref() == Some("") {
            return Err(Error::invalid_spec("region", "must not be empty"));
        }
        Ok(())
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
    #[serde(default)]
    pub name:         Option<String>,
    pub state:        SnapshotState,
    /// Kind of sandbox that can be created from this snapshot.
    #[serde(default)]
    pub sandbox_kind: Option<SandboxKind>,
    /// Provider regions in which this snapshot is available.
    #[serde(default)]
    pub regions:      Vec<String>,
    /// Default resources encoded in the snapshot.
    #[serde(default)]
    pub resources:    Option<Resources>,
    #[serde(default)]
    pub error_reason: Option<String>,
    #[serde(default)]
    pub size_bytes:   Option<u64>,
    #[serde(default)]
    pub created_at:   Option<SystemTime>,
}

impl SnapshotStatus {
    pub fn new(id: SnapshotId, state: SnapshotState) -> Self {
        Self {
            id,
            name: None,
            state,
            sandbox_kind: None,
            regions: Vec::new(),
            resources: None,
            error_reason: None,
            size_bytes: None,
            created_at: None,
        }
    }
}

/// Filter for [`SnapshotProvider::list`].
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(default)]
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
    #[serde(default)]
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
    #[serde(default)]
    pub name:         Option<String>,
    pub state:        VolumeState,
    #[serde(default)]
    pub error_reason: Option<String>,
    #[serde(default)]
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_spec_builder_sets_kind_region_and_resources() {
        let resources = Resources {
            cpu_cores: Some(2),
            ..Resources::default()
        };
        let spec = SnapshotSpec::new(SnapshotSource::Image {
            reference: "ubuntu:24.04".to_owned(),
        })
        .name("base")
        .sandbox_kind(SandboxKind::VirtualMachine)
        .region("eu")
        .resources(resources);

        assert_eq!(spec.name.as_deref(), Some("base"));
        assert_eq!(spec.sandbox_kind, Some(SandboxKind::VirtualMachine));
        assert_eq!(spec.region.as_deref(), Some("eu"));
        assert_eq!(spec.resources, resources);
        assert!(spec.validate().is_ok());
    }
}
