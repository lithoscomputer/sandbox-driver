use std::collections::BTreeMap;
use std::time::SystemTime;

use serde::{Deserialize, Serialize};

use crate::id::SandboxId;
use crate::sandbox::WorkspaceOwnership;
use crate::spec::Resources;

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
    pub state:               SandboxState,
    /// Provider's raw state string, e.g. Daytona's `"pulling_snapshot"`.
    #[serde(default)]
    pub provider_state:      String,
    #[serde(default)]
    pub error_reason:        Option<String>,
    #[serde(default)]
    pub resources:           Option<Resources>,
    #[serde(default)]
    pub labels:              BTreeMap<String, String>,
    /// Snapshot or image the sandbox was created from, when known.
    #[serde(default)]
    pub source:              Option<String>,
    /// Host provider only: who owns the workspace directory.
    #[serde(default)]
    pub workspace_ownership: Option<WorkspaceOwnership>,
    /// Provider console page for this sandbox, when the provider has one.
    #[serde(default)]
    pub web_url:             Option<String>,
    #[serde(default)]
    pub created_at:          Option<SystemTime>,
    #[serde(default)]
    pub updated_at:          Option<SystemTime>,
}

impl SandboxStatus {
    /// A status with the required fields; everything else defaults to empty.
    pub fn new(id: SandboxId, state: SandboxState) -> Self {
        Self {
            id,
            state,
            provider_state: String::new(),
            error_reason: None,
            resources: None,
            labels: BTreeMap::new(),
            source: None,
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
