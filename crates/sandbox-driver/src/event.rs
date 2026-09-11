use std::error::Error as StdError;
use std::fmt;
use std::future::Future;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant, SystemTime};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use crate::error::{Error, Result};
use crate::id::{ProviderKind, SandboxId, SnapshotId, VolumeId};
use crate::provider::{SnapshotState, VolumeState};
use crate::state::SandboxState;

/// An action performed by sandbox-driver on a provider resource.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Action {
    Create,
    Attach,
    Start,
    Stop,
    Delete,
    Activate,
    Deactivate,
    Pause,
    Resume,
    Archive,
    Fork,
    Resize,
    #[serde(alias = "snapshot_sandbox")]
    Snapshot,
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
/// wire.
///
/// The stable `kind` and `retryable` fields let consumers make decisions
/// without parsing the display message. Raw command output never enters the
/// report.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub struct ErrorReport {
    /// Stable snake_case error kind, for example `"unsupported"` or
    /// `"timeout"`.
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
            Error::NotOwned { .. } => "not_owned",
            Error::Unsupported { .. } => "unsupported",
            Error::InvalidState { .. } => "invalid_state",
            Error::InvalidSpec { .. } => "invalid_spec",
            Error::Timeout { .. } => "timeout",
            Error::Auth(_) => "auth",
            Error::RateLimited { .. } => "rate_limited",
            Error::Overloaded { .. } => "overloaded",
            Error::LimitExceeded { .. } => "limit_exceeded",
            Error::Exec(_) => "exec",
            Error::Git(_) => "git",
            Error::Provider(_) => "provider",
            Error::Transport(_) => "transport",
            Error::Incomplete(_) => "incomplete",
            Error::Io { .. } => "io",
        };
        let retryable = match error {
            Error::Timeout { .. } | Error::RateLimited { .. } | Error::Transport(_) => true,
            Error::Provider(provider) => provider.retryable,
            Error::Git(failure) => failure.kind().is_transient(),
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

macro_rules! generated_id {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            fn generate() -> Self {
                Self(format!("{:032x}", rand::random::<u128>()))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }
    };
}

generated_id!(
    /// Identifies one live event source. A new context creates a new source.
    EventSourceId
);
generated_id!(
    /// Correlates the events emitted by one driver operation.
    OperationId
);

/// Unique event identity within one live event source.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct EventId {
    source_id: EventSourceId,
    sequence:  u64,
}

impl EventId {
    pub fn source_id(&self) -> &EventSourceId {
        &self.source_id
    }

    pub fn sequence(&self) -> u64 {
        self.sequence
    }
}

impl fmt::Display for EventId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.source_id, self.sequence)
    }
}

/// Opaque consumer-supplied correlation value.
///
/// sandbox-driver never interprets this value. An application can use it to
/// associate events with a run, request, or job without adding application
/// concepts to this crate.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CorrelationId(String);

impl CorrelationId {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for CorrelationId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The resource or provider that an event describes.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
#[non_exhaustive]
pub enum EventSubject {
    Provider,
    Sandbox {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        id:   Option<SandboxId>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        name: Option<String>,
    },
    Snapshot {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        id:   Option<SnapshotId>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        name: Option<String>,
    },
    Volume {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        id:   Option<VolumeId>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        name: Option<String>,
    },
    /// A subject kind sent by a newer protocol peer.
    #[serde(other)]
    Unknown,
}

impl EventSubject {
    pub fn sandbox(id: impl Into<Option<SandboxId>>) -> Self {
        Self::Sandbox {
            id:   id.into(),
            name: None,
        }
    }

    pub fn pending_sandbox(name: Option<String>) -> Self {
        Self::Sandbox { id: None, name }
    }

    pub fn snapshot(id: impl Into<Option<SnapshotId>>) -> Self {
        Self::Snapshot {
            id:   id.into(),
            name: None,
        }
    }

    pub fn pending_snapshot(name: Option<String>) -> Self {
        Self::Snapshot { id: None, name }
    }

    pub fn volume(id: impl Into<Option<VolumeId>>) -> Self {
        Self::Volume {
            id:   id.into(),
            name: None,
        }
    }

    pub fn pending_volume(name: Option<String>) -> Self {
        Self::Volume { id: None, name }
    }
}

/// Stable, extensible progress code.
///
/// Consumers branch on this code and use `message` only for display.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ProgressCode(String);

impl ProgressCode {
    pub const IMAGE_PULL: &'static str = "image.pull";
    pub const RESOURCE_WAIT: &'static str = "resource.wait";
    pub const SANDBOX_PROVISION: &'static str = "sandbox.provision";
    pub const SNAPSHOT_BUILD: &'static str = "snapshot.build";

    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ProgressCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Unit used by structured progress measurements.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ProgressUnit {
    Bytes,
    Items,
    Steps,
    Percent,
    #[serde(other)]
    Unknown,
}

/// Structured progress for a long-running operation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Progress {
    pub code:      ProgressCode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message:   Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completed: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total:     Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unit:      Option<ProgressUnit>,
}

impl Progress {
    pub fn new(code: impl Into<String>) -> Self {
        Self {
            code:      ProgressCode::new(code),
            message:   None,
            completed: None,
            total:     None,
            unit:      None,
        }
    }

    #[must_use]
    pub fn message(mut self, message: impl Into<String>) -> Self {
        self.message = Some(message.into());
        self
    }

    #[must_use]
    pub fn amount(mut self, completed: u64, total: Option<u64>, unit: ProgressUnit) -> Self {
        self.completed = Some(completed);
        self.total = total;
        self.unit = Some(unit);
        self
    }
}

/// State value observed for a resource.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "resource", content = "state", rename_all = "snake_case")]
#[non_exhaustive]
pub enum ResourceState {
    Sandbox(SandboxState),
    Snapshot(SnapshotState),
    Volume(VolumeState),
    /// A resource kind sent by a newer protocol peer.
    #[serde(other)]
    Unknown,
}

/// Typed event payload.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
#[non_exhaustive]
pub enum EventBody {
    OperationStarted {
        action: Action,
    },
    OperationProgress {
        action:   Action,
        progress: Progress,
    },
    OperationCompleted {
        action:   Action,
        duration: Duration,
    },
    OperationFailed {
        action:   Action,
        duration: Duration,
        error:    ErrorReport,
    },
    StateObserved {
        previous: Option<ResourceState>,
        current:  ResourceState,
    },
    Notice {
        code:    String,
        message: String,
    },
    /// An event body sent by a newer protocol peer.
    #[serde(other)]
    Unknown,
}

impl EventBody {
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            Self::OperationCompleted { .. } | Self::OperationFailed { .. }
        )
    }
}

/// A discrete, low-volume fact emitted by sandbox-driver.
///
/// Exec output, PTY bytes, file-transfer chunks, and logs use their own
/// streaming APIs and never enter this event feed.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Event {
    pub id:             EventId,
    #[serde(with = "crate::wire_time")]
    pub occurred_at:    SystemTime,
    pub provider:       ProviderKind,
    pub subject:        EventSubject,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation_id:   Option<OperationId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub correlation_id: Option<CorrelationId>,
    #[serde(flatten)]
    pub body:           EventBody,
}

impl Event {
    pub fn source_id(&self) -> &EventSourceId {
        self.id.source_id()
    }

    pub fn sequence(&self) -> u64 {
        self.id.sequence()
    }
}

/// Consumer-defined event handoff boundary.
///
/// sandbox-driver awaits each observation. The observer decides whether
/// completion means an in-memory enqueue, durable persistence, or immediate
/// handling. Persistence failures remain an application concern because a
/// provider operation may already have taken effect.
///
/// Implementations must not panic. They must also not await another
/// operation that emits through the same [`EventContext`], because the
/// context serializes observation to preserve event order.
#[async_trait]
pub trait EventObserver: Send + Sync {
    async fn observe(&self, event: Event);
}

struct EventContextInner {
    source_id:     EventSourceId,
    next_sequence: Mutex<u64>,
    observer:      Arc<dyn EventObserver>,
}

/// Shared observer and sequence space for one live event source.
///
/// Clone this value when several handles or resource services should feed one
/// ordered consumer stream. Create a new context after reconnect when the
/// consumer wants an explicit source boundary.
#[derive(Clone)]
pub struct EventContext {
    inner:          Arc<EventContextInner>,
    correlation_id: Option<CorrelationId>,
}

impl fmt::Debug for EventContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EventContext")
            .field("source_id", &self.inner.source_id)
            .field("correlation_id", &self.correlation_id)
            .finish_non_exhaustive()
    }
}

impl EventContext {
    pub fn new(observer: Arc<dyn EventObserver>) -> Self {
        Self {
            inner:          Arc::new(EventContextInner {
                source_id: EventSourceId::generate(),
                next_sequence: Mutex::new(0),
                observer,
            }),
            correlation_id: None,
        }
    }

    #[must_use]
    pub fn correlation_id(mut self, correlation_id: CorrelationId) -> Self {
        self.correlation_id = Some(correlation_id);
        self
    }

    pub fn source_id(&self) -> &EventSourceId {
        &self.inner.source_id
    }

    pub fn correlation_id_ref(&self) -> Option<&CorrelationId> {
        self.correlation_id.as_ref()
    }

    /// Delivers an event that another sandbox-driver transport produced.
    ///
    /// The original envelope is preserved, including its source, sequence,
    /// timestamp, and operation identity.
    pub async fn forward(&self, event: Event) {
        self.inner.observer.observe(event).await;
    }

    async fn emit(
        &self,
        provider: ProviderKind,
        subject: EventSubject,
        operation_id: Option<OperationId>,
        body: EventBody,
    ) {
        let occurred_at = SystemTime::now();
        // Keep the lock through observer handoff. This gives one clear order
        // for a context and lets a slow observer apply bounded backpressure
        // without any hidden queue or detached task.
        let mut sequence = self.inner.next_sequence.lock().await;
        *sequence = sequence
            .checked_add(1)
            .expect("an event source cannot emit more than u64::MAX events");
        let event = Event {
            id: EventId {
                source_id: self.inner.source_id.clone(),
                sequence:  *sequence,
            },
            occurred_at,
            provider,
            subject,
            operation_id,
            correlation_id: self.correlation_id.clone(),
            body,
        };
        self.inner.observer.observe(event).await;
    }
}

/// Provider-facing event helper bound to one provider and optional consumer
/// context.
#[derive(Clone, Debug)]
pub struct EventEmitter {
    provider: ProviderKind,
    context:  Option<EventContext>,
}

impl EventEmitter {
    pub fn new(provider: ProviderKind, context: Option<EventContext>) -> Self {
        Self { provider, context }
    }

    pub fn disabled(provider: ProviderKind) -> Self {
        Self::new(provider, None)
    }

    /// Emits the complete lifecycle for one operation.
    ///
    /// The terminal event is handed to the observer before this future
    /// resolves. The operation closure uses [`OperationReporter`] for any
    /// structured progress it observes.
    pub async fn run<T, F, Fut>(
        &self,
        subject: EventSubject,
        action: Action,
        operation: F,
    ) -> Result<T>
    where
        F: FnOnce(OperationReporter) -> Fut,
        Fut: Future<Output = Result<T>>,
    {
        let operation_id = OperationId::generate();
        self.emit(
            subject.clone(),
            Some(operation_id.clone()),
            EventBody::OperationStarted { action },
        )
        .await;
        let current_subject = Arc::new(RwLock::new(subject));
        let reporter = OperationReporter {
            emitter: self.clone(),
            subject: Arc::clone(&current_subject),
            operation_id: operation_id.clone(),
            action,
        };
        let started = Instant::now();
        let outcome = operation(reporter).await;
        let duration = started.elapsed();
        let body = match &outcome {
            Ok(_) => EventBody::OperationCompleted { action, duration },
            Err(error) => EventBody::OperationFailed {
                action,
                duration,
                error: ErrorReport::from(error),
            },
        };
        let terminal_subject = current_subject
            .read()
            .expect("operation subject lock")
            .clone();
        self.emit(terminal_subject, Some(operation_id), body).await;
        outcome
    }

    pub async fn state_observed(
        &self,
        subject: EventSubject,
        previous: Option<ResourceState>,
        current: ResourceState,
    ) {
        self.emit(subject, None, EventBody::StateObserved {
            previous,
            current,
        })
        .await;
    }

    pub async fn notice(
        &self,
        subject: EventSubject,
        code: impl Into<String>,
        message: impl Into<String>,
    ) {
        self.emit(subject, None, EventBody::Notice {
            code:    code.into(),
            message: message.into(),
        })
        .await;
    }

    async fn emit(
        &self,
        subject: EventSubject,
        operation_id: Option<OperationId>,
        body: EventBody,
    ) {
        if let Some(context) = &self.context {
            context
                .emit(self.provider.clone(), subject, operation_id, body)
                .await;
        }
    }
}

/// Progress reporter for one in-flight operation.
#[derive(Clone, Debug)]
pub struct OperationReporter {
    emitter:      EventEmitter,
    subject:      Arc<RwLock<EventSubject>>,
    operation_id: OperationId,
    action:       Action,
}

impl OperationReporter {
    pub fn operation_id(&self) -> &OperationId {
        &self.operation_id
    }

    /// Updates the subject used by later progress and terminal events.
    ///
    /// Create operations use this after a provider assigns the resource id.
    pub fn set_subject(&self, subject: EventSubject) {
        *self.subject.write().expect("operation subject lock") = subject;
    }

    pub async fn progress(&self, progress: Progress) {
        let subject = self.subject.read().expect("operation subject lock").clone();
        self.emitter
            .emit(
                subject,
                Some(self.operation_id.clone()),
                EventBody::OperationProgress {
                    action: self.action,
                    progress,
                },
            )
            .await;
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex as StdMutex;

    use super::*;
    use crate::capabilities::Capability;

    #[derive(Default)]
    struct RecordingObserver {
        events: StdMutex<Vec<Event>>,
    }

    #[async_trait]
    impl EventObserver for RecordingObserver {
        async fn observe(&self, event: Event) {
            self.events.lock().expect("events lock").push(event);
        }
    }

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
    async fn operation_events_are_ordered_and_terminal_precedes_return() {
        let observer = Arc::new(RecordingObserver::default());
        let context = EventContext::new(observer.clone());
        let emitter = EventEmitter::new(
            ProviderKind::try_new("test").expect("valid provider"),
            Some(context),
        );

        let result = emitter
            .run(
                EventSubject::sandbox(None),
                Action::Create,
                |reporter| async move {
                    reporter
                        .progress(Progress::new(ProgressCode::SANDBOX_PROVISION))
                        .await;
                    reporter.set_subject(EventSubject::sandbox(Some(
                        SandboxId::try_new("sb-created").expect("valid id"),
                    )));
                    Ok::<_, Error>("sandbox")
                },
            )
            .await
            .expect("operation succeeds");
        assert_eq!(result, "sandbox");

        let events = observer.events.lock().expect("events lock");
        assert_eq!(events.len(), 3);
        assert!(matches!(events[0].body, EventBody::OperationStarted { .. }));
        assert!(matches!(
            events[1].body,
            EventBody::OperationProgress { .. }
        ));
        assert!(events[2].body.is_terminal());
        assert_eq!(events[0].sequence(), 1);
        assert_eq!(events[1].sequence(), 2);
        assert_eq!(events[2].sequence(), 3);
        assert_eq!(events[0].operation_id, events[1].operation_id);
        assert_eq!(events[1].operation_id, events[2].operation_id);
        assert!(matches!(events[0].subject, EventSubject::Sandbox {
            id: None,
            ..
        }));
        assert!(matches!(
            &events[2].subject,
            EventSubject::Sandbox { id: Some(id), .. } if id.as_str() == "sb-created"
        ));
    }

    #[tokio::test]
    async fn failed_operation_has_duration_and_error_report() {
        let observer = Arc::new(RecordingObserver::default());
        let context = EventContext::new(observer.clone());
        let emitter = EventEmitter::new(
            ProviderKind::try_new("test").expect("valid provider"),
            Some(context),
        );

        emitter
            .run(EventSubject::sandbox(None), Action::Create, |_| async {
                Err::<(), _>(Error::unsupported(Capability::LifecycleArchive))
            })
            .await
            .expect_err("operation fails");

        let events = observer.events.lock().expect("events lock");
        let EventBody::OperationFailed {
            action,
            duration: _,
            error,
        } = &events[1].body
        else {
            panic!("expected failed terminal event");
        };
        assert_eq!(*action, Action::Create);
        assert_eq!(error.kind, "unsupported");
    }
}
