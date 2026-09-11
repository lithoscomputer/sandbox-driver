use std::collections::BTreeMap;
use std::time::SystemTime;

use serde::{Deserialize, Serialize};

use crate::id::SandboxId;
use crate::sandbox::WorkspaceOwnership;
use crate::spec::{NetworkPolicy, Resources, SandboxKind};

/// Typed sandbox state for logic. The provider's raw state string travels
/// alongside in [`SandboxStatus::provider_state`] for display and debugging.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum SandboxState {
    Creating,
    Starting,
    Running,
    Stopping,
    Stopped,
    Pausing,
    Paused,
    Resuming,
    Archiving,
    Archived,
    Restoring,
    Resizing,
    Forking,
    Snapshotting,
    Deleting,
    Deleted,
    Error,
    #[serde(other)]
    Unknown,
}

impl SandboxState {
    /// Whether this state is a settled (non-transitional) state.
    pub fn is_stable(self) -> bool {
        matches!(
            self,
            Self::Running
                | Self::Stopped
                | Self::Paused
                | Self::Archived
                | Self::Deleted
                | Self::Error
        )
    }
}

/// Observed status of a sandbox, returned by [`crate::Sandbox::describe`].
///
/// Constructed with [`SandboxStatus::new`]; optional fields are set by
/// mutating the public fields. The struct is `#[non_exhaustive]` so fields
/// can be added compatibly.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub struct SandboxStatus {
    pub id:                  SandboxId,
    /// Provider display name. This is not the stable provider identifier.
    #[serde(default)]
    pub name:                Option<String>,
    pub state:               SandboxState,
    /// Provider's raw state string, e.g. Daytona's `"pulling_snapshot"`.
    #[serde(default)]
    pub provider_state:      String,
    #[serde(default)]
    pub error_reason:        Option<String>,
    #[serde(default)]
    pub resources:           Option<Resources>,
    /// Observed provisioning kind. This is not an isolation guarantee.
    #[serde(default)]
    pub sandbox_kind:        Option<SandboxKind>,
    /// Provider region or target in which the sandbox runs.
    #[serde(default)]
    pub region:              Option<String>,
    #[serde(default)]
    pub labels:              BTreeMap<String, String>,
    /// The image the sandbox runs, when the provider knows it: a Docker
    /// container's image reference.
    #[serde(default)]
    pub image:               Option<String>,
    /// The snapshot the sandbox was created from, when the provider knows
    /// it: a Daytona snapshot name.
    #[serde(default)]
    pub snapshot:            Option<String>,
    /// The network policy in force, when the provider can read it back.
    /// `None` when the provider cannot tell (a Docker container on a
    /// sidecar network, a Host sandbox).
    #[serde(default)]
    pub network:             Option<NetworkPolicy>,
    /// Host provider only: who owns the workspace directory.
    #[serde(default)]
    pub workspace_ownership: Option<WorkspaceOwnership>,
    /// Provider console page for this sandbox, when the provider has one.
    #[serde(default)]
    pub web_url:             Option<String>,
    #[serde(default, with = "crate::wire_time::option")]
    pub created_at:          Option<SystemTime>,
    #[serde(default, with = "crate::wire_time::option")]
    pub updated_at:          Option<SystemTime>,
}

impl SandboxStatus {
    /// A status with the required fields; everything else defaults to empty.
    pub fn new(id: SandboxId, state: SandboxState) -> Self {
        Self {
            id,
            name: None,
            state,
            provider_state: String::new(),
            error_reason: None,
            resources: None,
            sandbox_kind: None,
            region: None,
            labels: BTreeMap::new(),
            image: None,
            snapshot: None,
            network: None,
            workspace_ownership: None,
            web_url: None,
            created_at: None,
            updated_at: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stable_states_are_the_settled_ones() {
        assert!(SandboxState::Running.is_stable());
        assert!(SandboxState::Error.is_stable());
        assert!(!SandboxState::Starting.is_stable());
        assert!(!SandboxState::Snapshotting.is_stable());
    }
}
