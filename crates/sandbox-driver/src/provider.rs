use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio::time::{Instant, sleep};

use crate::capabilities::{Capabilities, Capability};
use crate::error::{Error, ProviderError, ResourceKind, Result};
use crate::event::EventContext;
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

    /// Provisions a sandbox and returns its handle. The event context is
    /// scoped to the returned handle's lifetime.
    async fn create(
        &self,
        spec: &SandboxSpec,
        events: Option<EventContext>,
    ) -> Result<Arc<dyn Sandbox>>;

    /// Re-attaches to an existing sandbox by persisted ID.
    async fn attach(
        &self,
        id: &SandboxId,
        events: Option<EventContext>,
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
        events: Option<EventContext>,
    ) -> Result<Arc<dyn Sandbox>> {
        let _ = (id, events);
        Err(Error::unsupported(Capability::LifecycleUndelete))
    }

    /// Deletes a sandbox by ID without building a handle first.
    ///
    /// Idempotent: an ID the provider does not know, or a sandbox already
    /// deleted, succeeds. This is the call for a reconciler that sweeps
    /// what an earlier process left behind: it needs no working handle,
    /// so a sandbox that is stopped, wedged, or half-created is removed
    /// the same as a running one. The default attaches and deletes, which
    /// is correct for every provider; a provider overrides it when it can
    /// remove the sandbox from its own records or backend directly.
    async fn delete(&self, id: &SandboxId, events: Option<EventContext>) -> Result<()> {
        match self.attach(id, events).await {
            Ok(sandbox) => sandbox.delete().await,
            Err(Error::NotFound {
                resource: ResourceKind::Sandbox,
                ..
            }) => Ok(()),
            Err(error) => Err(error),
        }
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
    pub status:               HealthStatus,
    /// Human-readable detail: which check failed and what to fix.
    #[serde(default)]
    pub message:              Option<String>,
    /// Permissions the credential is missing, when the provider can
    /// enumerate them (e.g. Daytona API key scopes), in the order of
    /// [`Self::required_permissions`].
    #[serde(default)]
    pub missing_permissions:  Vec<String>,
    /// Every permission the provider's operations need, in the order an
    /// operator should read them when regenerating a credential; the list
    /// `missing_permissions` is drawn from. Empty when the provider cannot
    /// enumerate its credential's permissions.
    #[serde(default)]
    pub required_permissions: Vec<String>,
    /// Stable, non-secret identity of the backend's resource namespace,
    /// such as a cloud organization ID. Credential rotation must preserve
    /// it when the replacement credential addresses the same resources.
    /// Hosts can combine this with the endpoint to protect recovery from
    /// accidentally attaching or deleting resources in another account.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity:             Option<String>,
}

impl ProviderHealth {
    pub fn new(status: HealthStatus) -> Self {
        Self {
            status,
            message: None,
            missing_permissions: Vec::new(),
            required_permissions: Vec::new(),
            identity: None,
        }
    }
}

/// Snapshot management for one provider.
#[async_trait]
pub trait SnapshotProvider: Send + Sync {
    /// Starts creating a snapshot; poll [`SnapshotProvider::get`] or follow
    /// [`SnapshotProvider::build_logs`] for progress.
    async fn create(&self, spec: &SnapshotSpec, events: Option<EventContext>)
    -> Result<SnapshotId>;

    async fn get(&self, id: &SnapshotId) -> Result<SnapshotStatus>;

    async fn list(&self, filter: &SnapshotFilter) -> Result<Vec<SnapshotStatus>>;

    /// Idempotent delete.
    async fn delete(&self, id: &SnapshotId, events: Option<EventContext>) -> Result<()>;

    /// Streams snapshot build output. Capability-gated on
    /// `snapshots.build_logs`.
    async fn build_logs(&self, id: &SnapshotId, follow: bool, sink: LogSink) -> Result<()> {
        let _ = (id, follow, sink);
        Err(Error::unsupported(Capability::Snapshots))
    }

    /// Reactivates an inactive snapshot so sandboxes can be created from
    /// it again (Daytona deactivates snapshots unused for two weeks).
    /// Capability-gated on `snapshots.activation`.
    async fn activate(&self, id: &SnapshotId, events: Option<EventContext>) -> Result<()> {
        let _ = (id, events);
        Err(Error::unsupported(Capability::SnapshotsActivation))
    }

    /// Deactivates an active snapshot, releasing whatever the provider
    /// keeps warm for it. Capability-gated on `snapshots.activation`.
    async fn deactivate(&self, id: &SnapshotId, events: Option<EventContext>) -> Result<()> {
        let _ = (id, events);
        Err(Error::unsupported(Capability::SnapshotsActivation))
    }

    /// Makes the snapshot named by `spec.name` usable and returns its id,
    /// whatever state it starts in: an active snapshot is returned at
    /// once, an inactive one is activated, a missing one is created from
    /// `spec`, and a building one is waited for. The wait polls
    /// [`SnapshotProvider::get`] with a growing interval until the
    /// snapshot is active, fails with the provider's reason when it
    /// enters the error state or starts deleting, and fails with
    /// [`Error::Timeout`] once `budget` has passed. `events` reach the
    /// create or activate operation this runs.
    ///
    /// The default is composed from the other methods, so it holds for
    /// every provider and both transports without a wire method of its
    /// own; a provider with a native equivalent may override it.
    async fn ensure(
        &self,
        spec: &SnapshotSpec,
        budget: Duration,
        events: Option<EventContext>,
    ) -> Result<SnapshotId> {
        ensure_snapshot(self, spec, budget, events).await
    }
}

/// First poll interval of [`SnapshotProvider::ensure`]; doubles up to
/// [`ENSURE_MAX_POLL`]. An image pull settles in seconds, a Dockerfile
/// build in minutes, and neither is helped by a tight loop.
const ENSURE_FIRST_POLL: Duration = Duration::from_secs(2);
const ENSURE_MAX_POLL: Duration = Duration::from_secs(30);

async fn ensure_snapshot<P: SnapshotProvider + ?Sized>(
    provider: &P,
    spec: &SnapshotSpec,
    budget: Duration,
    events: Option<EventContext>,
) -> Result<SnapshotId> {
    let Some(name) = spec.name.as_deref() else {
        return Err(Error::invalid_spec(
            "name",
            "ensure looks a snapshot up by name, so the spec must carry one",
        ));
    };
    let started = Instant::now();
    let filter = SnapshotFilter {
        name: Some(name.to_owned()),
    };
    let existing = provider
        .list(&filter)
        .await?
        .into_iter()
        .find(|status| status.name.as_deref() == Some(name));
    let id = match existing {
        Some(status) => match status.state {
            SnapshotState::Active => return Ok(status.id),
            SnapshotState::Error | SnapshotState::Deleting => {
                return Err(snapshot_unusable(name, &status));
            }
            SnapshotState::Inactive => {
                provider.activate(&status.id, events).await?;
                status.id
            }
            SnapshotState::Building | SnapshotState::Unknown => status.id,
        },
        None => provider.create(spec, events).await?,
    };

    let mut interval = ENSURE_FIRST_POLL;
    loop {
        let elapsed = started.elapsed();
        if elapsed >= budget {
            return Err(Error::Timeout {
                operation: format!("waiting for snapshot {name:?} to become active"),
                elapsed,
            });
        }
        sleep(interval.min(budget.saturating_sub(elapsed))).await;
        let status = provider.get(&id).await?;
        tracing::debug!(snapshot = name, state = ?status.state, "snapshot state observed");
        match status.state {
            SnapshotState::Active => return Ok(id),
            SnapshotState::Error | SnapshotState::Deleting => {
                return Err(snapshot_unusable(name, &status));
            }
            SnapshotState::Building | SnapshotState::Inactive | SnapshotState::Unknown => {
                interval = (interval * 2).min(ENSURE_MAX_POLL);
            }
        }
    }
}

/// The failure for a snapshot that cannot become active, carrying the
/// provider's reason the way [`crate::wait_for_state`] does for a sandbox.
fn snapshot_unusable(name: &str, status: &SnapshotStatus) -> Error {
    let reason = status
        .error_reason
        .clone()
        .unwrap_or_else(|| format!("snapshot is in state {:?}", status.state));
    Error::Provider(ProviderError::new(
        ProviderKind::try_new("unknown").expect("static kind is valid"),
        format!("snapshot {name:?} cannot become active: {reason}"),
    ))
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
    async fn create(&self, spec: &VolumeSpec, events: Option<EventContext>) -> Result<VolumeId>;

    async fn get(&self, id: &VolumeId) -> Result<VolumeStatus>;

    async fn list(&self) -> Result<Vec<VolumeStatus>>;

    /// Idempotent delete.
    async fn delete(&self, id: &VolumeId, events: Option<EventContext>) -> Result<()>;
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
    use std::collections::VecDeque;
    use std::sync::Mutex;

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

    /// A snapshot provider that replays scripted `get` states and records
    /// the mutating calls it receives.
    struct ScriptedSnapshots {
        listed: Vec<SnapshotStatus>,
        states: Mutex<VecDeque<SnapshotState>>,
        calls:  Mutex<Vec<&'static str>>,
    }

    impl ScriptedSnapshots {
        fn new(listed: Vec<SnapshotStatus>, states: Vec<SnapshotState>) -> Self {
            Self {
                listed,
                states: Mutex::new(states.into_iter().collect()),
                calls: Mutex::new(Vec::new()),
            }
        }

        fn calls(&self) -> Vec<&'static str> {
            self.calls.lock().expect("calls lock").clone()
        }
    }

    fn snapshot_id(text: &str) -> SnapshotId {
        SnapshotId::try_new(text).expect("valid id")
    }

    fn named_status(text: &str, state: SnapshotState) -> SnapshotStatus {
        let mut status = SnapshotStatus::new(snapshot_id(text), state);
        status.name = Some("fabro-snap".to_owned());
        status
    }

    fn named_spec() -> SnapshotSpec {
        SnapshotSpec::new(SnapshotSource::Image {
            reference: "ubuntu:24.04".to_owned(),
        })
        .name("fabro-snap")
    }

    #[async_trait]
    impl SnapshotProvider for ScriptedSnapshots {
        async fn create(
            &self,
            spec: &SnapshotSpec,
            _events: Option<EventContext>,
        ) -> Result<SnapshotId> {
            assert_eq!(spec.name.as_deref(), Some("fabro-snap"));
            self.calls.lock().expect("calls lock").push("create");
            Ok(snapshot_id("created"))
        }

        async fn get(&self, id: &SnapshotId) -> Result<SnapshotStatus> {
            self.calls.lock().expect("calls lock").push("get");
            let state = self
                .states
                .lock()
                .expect("states lock")
                .pop_front()
                .expect("a scripted state for every poll");
            Ok(SnapshotStatus::new(id.clone(), state))
        }

        async fn list(&self, filter: &SnapshotFilter) -> Result<Vec<SnapshotStatus>> {
            assert_eq!(filter.name.as_deref(), Some("fabro-snap"));
            self.calls.lock().expect("calls lock").push("list");
            Ok(self.listed.clone())
        }

        async fn delete(&self, _id: &SnapshotId, _events: Option<EventContext>) -> Result<()> {
            unreachable!("ensure never deletes")
        }

        async fn activate(&self, _id: &SnapshotId, _events: Option<EventContext>) -> Result<()> {
            self.calls.lock().expect("calls lock").push("activate");
            Ok(())
        }
    }

    #[tokio::test(start_paused = true)]
    async fn ensure_returns_an_active_snapshot_without_a_poll() {
        let provider =
            ScriptedSnapshots::new(vec![named_status("live", SnapshotState::Active)], vec![]);
        let id = provider
            .ensure(&named_spec(), Duration::from_secs(60), None)
            .await
            .expect("ensure");
        assert_eq!(id.as_str(), "live");
        assert_eq!(provider.calls(), ["list"]);
    }

    #[tokio::test(start_paused = true)]
    async fn ensure_creates_a_missing_snapshot_and_waits_with_a_growing_interval() {
        let provider = ScriptedSnapshots::new(vec![], vec![
            SnapshotState::Building,
            SnapshotState::Building,
            SnapshotState::Active,
        ]);
        let started = Instant::now();
        let id = provider
            .ensure(&named_spec(), Duration::from_secs(600), None)
            .await
            .expect("ensure");
        assert_eq!(id.as_str(), "created");
        assert_eq!(provider.calls(), ["list", "create", "get", "get", "get"]);
        // Polls after 2s, 4s, and 8s.
        assert_eq!(started.elapsed(), Duration::from_secs(14));
    }

    #[tokio::test(start_paused = true)]
    async fn ensure_activates_an_inactive_snapshot_then_waits() {
        let provider =
            ScriptedSnapshots::new(vec![named_status("cold", SnapshotState::Inactive)], vec![
                SnapshotState::Active,
            ]);
        let id = provider
            .ensure(&named_spec(), Duration::from_secs(60), None)
            .await
            .expect("ensure");
        assert_eq!(id.as_str(), "cold");
        assert_eq!(provider.calls(), ["list", "activate", "get"]);
    }

    #[tokio::test(start_paused = true)]
    async fn ensure_reports_the_providers_reason_for_a_failed_snapshot() {
        let mut failed = named_status("broken", SnapshotState::Error);
        failed.error_reason = Some("base image not found".to_owned());
        let provider = ScriptedSnapshots::new(vec![failed], vec![]);
        let error = provider
            .ensure(&named_spec(), Duration::from_secs(60), None)
            .await
            .expect_err("errored snapshot fails");
        assert!(
            error.to_string().contains("base image not found"),
            "{error}"
        );
        assert_eq!(provider.calls(), ["list"]);
    }

    #[tokio::test(start_paused = true)]
    async fn ensure_times_out_when_a_build_outlives_the_budget() {
        let provider = ScriptedSnapshots::new(vec![], vec![SnapshotState::Building; 8]);
        let error = provider
            .ensure(&named_spec(), Duration::from_secs(10), None)
            .await
            .expect_err("budget exhausted");
        assert!(matches!(error, Error::Timeout { .. }), "{error}");
        // Polls at 2s, 6s, and 10s (the last sleep is cut to the budget);
        // none starts past it.
        assert_eq!(provider.calls(), ["list", "create", "get", "get", "get"]);
    }

    #[tokio::test]
    async fn ensure_needs_a_name() {
        let provider = ScriptedSnapshots::new(vec![], vec![]);
        let mut spec = named_spec();
        spec.name = None;
        let error = provider
            .ensure(&spec, Duration::from_secs(60), None)
            .await
            .expect_err("unnamed spec is rejected");
        assert!(matches!(error, Error::InvalidSpec { .. }), "{error}");
        assert!(provider.calls().is_empty());
    }
}
