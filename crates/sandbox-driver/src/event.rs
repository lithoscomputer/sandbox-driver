use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::state::SandboxState;

/// Lifecycle verbs, used in events and `InvalidState` errors.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum LifecycleAction {
    Create,
    Start,
    Stop,
    Delete,
    Pause,
    Resume,
    Archive,
    Fork,
    Checkpoint,
    RestoreCheckpoint,
    Resize,
    SnapshotSandbox,
    Recover,
    RefreshActivity,
    SetTimers,
    SetLabels,
    UpdateNetwork,
}

/// Progress events emitted while a provider works.
///
/// Delivery contract: in-order per sandbox, best-effort, no replay on
/// re-attach — durable state is [`crate::Sandbox::describe`]. Providers
/// invoke the callback from their own task; under pressure `Progress`
/// events may be dropped, but terminal `ActionCompleted`/`ActionFailed`
/// events are never dropped.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
#[non_exhaustive]
pub enum SandboxEvent {
    ActionStarted {
        action: LifecycleAction,
    },
    ActionCompleted {
        action:   LifecycleAction,
        duration: Duration,
    },
    ActionFailed {
        action: LifecycleAction,
        error:  String,
        causes: Vec<String>,
    },
    SnapshotBuilding {
        name: String,
    },
    SnapshotReady {
        name:     String,
        duration: Duration,
    },
    SnapshotFailed {
        name:  String,
        error: String,
    },
    StateChanged {
        from: SandboxState,
        to:   SandboxState,
    },
    /// Free-form progress inside a long action (image pull, snapshot poll).
    Progress {
        action:  LifecycleAction,
        message: String,
    },
}

/// Event delivery callback, attached at `create`/`attach` and scoped to
/// that handle's lifetime.
pub type EventCallback = Arc<dyn Fn(SandboxEvent) + Send + Sync>;
