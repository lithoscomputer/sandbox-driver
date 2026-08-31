use std::error::Error as StdError;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::error::Error;
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
    Resize,
    SnapshotSandbox,
    Recover,
    Undelete,
    RefreshActivity,
    SetTimers,
    SetLabels,
    UpdateNetwork,
    /// An action sent by a protocol peer that this version does not model.
    #[serde(other)]
    Unknown,
}

const MAX_CAUSES: usize = 8;
const MAX_CAUSE_CHARS: usize = 500;

/// Bounded, serializable projection of an [`Error`] for events and the
/// wire. Keeps a stable machine-readable `kind` alongside the rendered
/// message so the taxonomy survives the boundary; raw command output never
/// enters it (the underlying `Display` impls already omit it).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub struct ErrorReport {
    /// Stable snake_case error kind, e.g. `"unsupported"`, `"timeout"`.
    pub kind:      String,
    pub message:   String,
    #[serde(default)]
    pub retryable: bool,
    /// Rendered source chain, bounded in count and length.
    #[serde(default)]
    pub causes:    Vec<String>,
}

impl ErrorReport {
    pub fn new(kind: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            kind:      kind.into(),
            message:   message.into(),
            retryable: false,
            causes:    Vec::new(),
        }
    }
}

impl From<&Error> for ErrorReport {
    fn from(error: &Error) -> Self {
        let kind = match error {
            Error::NotFound { .. } => "not_found",
            Error::Unsupported { .. } => "unsupported",
            Error::InvalidState { .. } => "invalid_state",
            Error::InvalidSpec { .. } => "invalid_spec",
            Error::Timeout { .. } => "timeout",
            Error::Auth(_) => "auth",
            Error::RateLimited { .. } => "rate_limited",
            Error::Exec(_) => "exec",
            Error::Provider(_) => "provider",
            Error::Transport(_) => "transport",
            Error::Io { .. } => "io",
        };
        let retryable = match error {
            Error::Timeout { .. } | Error::RateLimited { .. } | Error::Transport(_) => true,
            Error::Provider(provider) => provider.retryable,
            _ => false,
        };
        let mut causes = Vec::new();
        let mut source = error.source();
        while let Some(cause) = source {
            if causes.len() >= MAX_CAUSES {
                break;
            }
            let mut text = cause.to_string();
            if text.len() > MAX_CAUSE_CHARS {
                let mut end = MAX_CAUSE_CHARS;
                while !text.is_char_boundary(end) {
                    end -= 1;
                }
                text.truncate(end);
                text.push('…');
            }
            causes.push(text);
            source = cause.source();
        }
        Self {
            kind: kind.to_owned(),
            message: error.to_string(),
            retryable,
            causes,
        }
    }
}

/// Progress events emitted while a provider works.
///
/// Delivery contract: in-order per sandbox, best-effort, no replay on
/// re-attach — durable state is [`crate::Sandbox::describe`]. Terminal
/// events (`ActionCompleted`, `ActionFailed`, `SnapshotReady`,
/// `SnapshotFailed`) are never dropped; `Progress` and `StateChanged` may
/// be dropped under pressure. See [`EventDispatcher`] for the delivery
/// mechanism providers are expected to use.
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
        error:  ErrorReport,
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
        error: ErrorReport,
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

impl SandboxEvent {
    /// Whether this event must never be dropped by a dispatcher.
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            Self::ActionCompleted { .. }
                | Self::ActionFailed { .. }
                | Self::SnapshotReady { .. }
                | Self::SnapshotFailed { .. }
        )
    }
}

/// Event delivery callback, attached at `create`/`attach` and scoped to
/// that handle's lifetime. Called from a dispatcher-owned task, never
/// from provider internals directly.
pub type EventCallback = Arc<dyn Fn(SandboxEvent) + Send + Sync>;

const DISPATCH_QUEUE_CAPACITY: usize = 256;

/// The one correct event-delivery mechanism, for providers to own inside
/// a sandbox handle.
///
/// A bounded queue feeds a single worker task that invokes the callback,
/// so a slow or panicking callback never blocks provider internals: a
/// panic stops further delivery (the worker keeps draining), overflow
/// drops only non-terminal events, and terminal events await queue space
/// instead of being dropped. The worker is owned, not detached — it ends
/// when the dispatcher is dropped (after draining what was queued) and
/// can be joined explicitly with [`EventDispatcher::shutdown`].
#[must_use = "hold the dispatcher for the sandbox handle's lifetime; dropping it ends delivery"]
#[derive(Debug)]
pub struct EventDispatcher {
    queue:  mpsc::Sender<SandboxEvent>,
    worker: JoinHandle<()>,
}

impl EventDispatcher {
    /// Starts the delivery worker on the current Tokio runtime.
    pub fn new(callback: EventCallback) -> Self {
        let (queue, mut receiver) = mpsc::channel::<SandboxEvent>(DISPATCH_QUEUE_CAPACITY);
        let worker = tokio::spawn(async move {
            let mut panicked = false;
            while let Some(event) = receiver.recv().await {
                if panicked {
                    continue; // Keep draining so senders never block.
                }
                let call = AssertUnwindSafe(|| callback(event));
                if catch_unwind(call).is_err() {
                    panicked = true;
                }
            }
        });
        Self { queue, worker }
    }

    /// Queues an event. Terminal events wait for queue space; others are
    /// dropped when the queue is full.
    pub async fn emit(&self, event: SandboxEvent) {
        if event.is_terminal() {
            // The receiver only closes when the dispatcher drops, so a
            // send failure here means shutdown is racing; dropping the
            // event then is correct.
            let _ = self.queue.send(event).await;
        } else {
            let _ = self.queue.try_send(event);
        }
    }

    /// Closes the queue, delivers what was queued, and joins the worker.
    pub async fn shutdown(self) {
        drop(self.queue);
        let _ = self.worker.await;
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;
    use crate::capabilities::Capability;

    #[test]
    fn error_report_keeps_a_stable_kind_and_retry_hint() {
        let report = ErrorReport::from(&Error::unsupported(Capability::LifecyclePause));
        assert_eq!(report.kind, "unsupported");
        assert!(!report.retryable);

        let report = ErrorReport::from(&Error::Timeout {
            operation: "waiting".into(),
            elapsed:   Duration::from_secs(1),
        });
        assert_eq!(report.kind, "timeout");
        assert!(report.retryable);
    }

    #[tokio::test]
    async fn dispatcher_delivers_in_order_and_survives_panics() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let calls = Arc::new(AtomicUsize::new(0));
        let seen_in_callback = Arc::clone(&seen);
        let calls_in_callback = Arc::clone(&calls);
        let dispatcher = EventDispatcher::new(Arc::new(move |event| {
            let call = calls_in_callback.fetch_add(1, Ordering::SeqCst);
            assert!(call != 1, "callback failure");
            seen_in_callback.lock().expect("seen lock").push(event);
        }));

        dispatcher
            .emit(SandboxEvent::ActionStarted {
                action: LifecycleAction::Create,
            })
            .await;
        dispatcher
            .emit(SandboxEvent::ActionCompleted {
                action:   LifecycleAction::Create,
                duration: Duration::from_millis(1),
            })
            .await;
        dispatcher
            .emit(SandboxEvent::ActionStarted {
                action: LifecycleAction::Start,
            })
            .await;
        dispatcher.shutdown().await;

        // First event delivered; second panicked; delivery then stops.
        let seen = seen.lock().expect("seen lock");
        assert_eq!(seen.len(), 1);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }
}
