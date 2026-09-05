use std::error::Error as StdError;
use std::result::Result as StdResult;
use std::sync::Arc;
use std::time::Duration;
use std::{fmt, io};

use crate::capabilities::Capability;
use crate::event::Action;
use crate::exec::Termination;
use crate::id::ProviderKind;
use crate::state::SandboxState;

/// Result alias for this crate's error surface.
pub type Result<T, E = Error> = StdResult<T, E>;

/// Which resource type an operation addressed.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ResourceKind {
    Sandbox,
    Snapshot,
    Volume,
    /// A plugin binary, in discovery errors.
    Plugin,
    /// A file inside a sandbox, from the filesystem facet. `id` is the
    /// path as the caller gave it.
    File,
    /// A resource kind sent by a protocol peer that this version does not
    /// model.
    #[serde(other)]
    Unknown,
}

/// The crate's boundary error.
///
/// Variants are caller-decision oriented: `Unsupported` is preflightable,
/// `NotFound` and `InvalidState` are recoverable branches, and `Provider`
/// carries structured provider detail without exposing SDK error types.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error("{resource:?} {id:?} was not found")]
    NotFound {
        resource: ResourceKind,
        id:       String,
    },

    /// The provider does not support this capability. Machine-readable so
    /// callers can preflight against [`crate::Capabilities`] instead.
    #[error("capability {capability} is not supported by this provider")]
    Unsupported { capability: Capability },

    #[error("cannot {action:?} a sandbox in state {current:?}")]
    InvalidState {
        current: SandboxState,
        action:  Action,
    },

    #[error("invalid spec: {field}: {reason}")]
    InvalidSpec { field: String, reason: String },

    #[error("{operation} timed out after {elapsed:?}")]
    Timeout {
        operation: String,
        elapsed:   Duration,
    },

    #[error(transparent)]
    Auth(#[from] AuthError),

    #[error("rate limited{}", retry_after.map(|d| format!(", retry after {d:?}")).unwrap_or_default())]
    RateLimited { retry_after: Option<Duration> },

    /// Admission failed before provider work started. The caller may retry.
    #[error("transport capacity exhausted: {limit}; operation did not start")]
    Overloaded { limit: String },

    /// A complete buffered value could not be provided. This does not imply
    /// that a command or write had no effects.
    #[error("{limit} exceeds the {max_bytes} byte buffer limit")]
    LimitExceeded { limit: String, max_bytes: usize },

    /// A command inside the sandbox failed in a way the caller did not run
    /// it to observe (probe failures, derived-operation failures).
    #[error(transparent)]
    Exec(#[from] ExecFailure),

    #[error(transparent)]
    Provider(#[from] ProviderError),

    /// Communication with an out-of-process provider failed.
    #[error(transparent)]
    Transport(#[from] TransportError),

    /// Local waiting ended without establishing a complete operation outcome.
    #[error(transparent)]
    Incomplete(#[from] IncompleteOperation),

    /// Local I/O failure (uploads, downloads, spawning).
    #[error("{context}")]
    Io {
        context: String,
        #[source]
        source:  io::Error,
    },
}

/// Facts established when local operation waiting ends. A stop acknowledgment
/// confirms receipt of a control request, not termination or resource cleanup.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, thiserror::Error)]
#[error(
    "{operation} is incomplete; output abandoned: {output_abandoned}, stop acknowledged: {stop_acknowledged}, termination confirmed: {termination_confirmed}, cleanup confirmed: {cleanup_confirmed}"
)]
#[non_exhaustive]
pub struct IncompleteOperation {
    pub operation:             String,
    pub output_abandoned:      bool,
    pub stop_acknowledged:     bool,
    pub termination_confirmed: bool,
    pub cleanup_confirmed:     bool,
}
impl IncompleteOperation {
    pub fn new(operation: impl Into<String>) -> Self {
        Self {
            operation:             operation.into(),
            output_abandoned:      true,
            stop_acknowledged:     false,
            termination_confirmed: false,
            cleanup_confirmed:     false,
        }
    }
}

impl Error {
    /// Convenience constructor for the `Unsupported` variant, used by the
    /// provided default bodies of optional trait methods.
    pub fn unsupported(capability: Capability) -> Self {
        Self::Unsupported { capability }
    }

    /// Convenience constructor for the `InvalidSpec` variant.
    pub fn invalid_spec(field: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::InvalidSpec {
            field:  field.into(),
            reason: reason.into(),
        }
    }

    /// Convenience constructor for the `Io` variant.
    pub fn io(context: impl Into<String>, source: io::Error) -> Self {
        Self::Io {
            context: context.into(),
            source,
        }
    }
}

/// Authentication or authorization failure against a provider.
#[derive(Debug)]
#[non_exhaustive]
pub struct AuthError {
    pub provider: ProviderKind,
    pub reason:   String,
    source:       Option<Box<OpaqueSource>>,
}

#[derive(Clone, Debug)]
struct OpaqueSource(Arc<dyn StdError + Send + Sync>);

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "authentication with {} failed: {}",
            self.provider, self.reason
        )
    }
}

impl StdError for AuthError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        self.source
            .as_ref()
            .map(|source| source.0.as_ref() as &(dyn StdError + 'static))
    }
}

impl AuthError {
    pub fn new(provider: ProviderKind, reason: impl Into<String>) -> Self {
        Self {
            provider,
            reason: reason.into(),
            source: None,
        }
    }

    /// Creates an authentication failure while preserving its infrastructure
    /// cause without exposing the cause type in the public API.
    pub fn with_source<E>(provider: ProviderKind, reason: impl Into<String>, source: E) -> Self
    where
        E: StdError + Send + Sync + 'static,
    {
        Self {
            provider,
            reason: reason.into(),
            source: Some(Box::new(OpaqueSource(Arc::new(source)))),
        }
    }
}

/// A failed command execution, with bounded classified metadata in
/// `Display` and raw output behind explicit accessors so callers control
/// exposure. Secret redaction is the caller's responsibility.
#[derive(Debug)]
pub struct ExecFailure {
    label:       String,
    termination: Termination,
    exit_code:   Option<i32>,
    stdout:      Vec<u8>,
    stderr:      Vec<u8>,
    duration:    Option<Duration>,
}

impl fmt::Display for ExecFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "command {:?} failed ({:?}, exit code {:?})",
            self.label, self.termination, self.exit_code
        )?;
        if let Some(duration) = self.duration {
            write!(f, " after {} ms", duration.as_millis())?;
        }
        if let Some(hint) = self.hint() {
            write!(f, " — hint: {hint}")?;
        }
        Ok(())
    }
}

impl StdError for ExecFailure {}

impl ExecFailure {
    /// A bounded diagnosis matched from stderr — static text only, so
    /// the redaction boundary holds: raw output never enters `Display`.
    /// Only provider-agnostic classes live here; fabro keeps its
    /// git-push classifications caller-side.
    fn hint(&self) -> Option<&'static str> {
        let stderr = String::from_utf8_lossy(&self.stderr).to_ascii_lowercase();
        if stderr.contains("could not resolve host") || stderr.contains("network is unreachable") {
            Some("network failure inside the sandbox — check DNS / egress")
        } else if stderr.contains("not a git repository")
            || stderr.contains("does not appear to be a git repository")
        {
            Some("no git repository at the working directory")
        } else {
            None
        }
    }

    pub fn new(
        label: impl Into<String>,
        termination: Termination,
        exit_code: Option<i32>,
        stdout: Vec<u8>,
        stderr: Vec<u8>,
    ) -> Self {
        Self {
            label: label.into(),
            termination,
            exit_code,
            stdout,
            stderr,
            duration: None,
        }
    }

    /// How long the command ran before failing, when the reporter
    /// observed it (fabro's exec errors carried this).
    #[must_use]
    pub fn with_duration(mut self, duration: Duration) -> Self {
        self.duration = Some(duration);
        self
    }

    pub fn duration(&self) -> Option<Duration> {
        self.duration
    }

    /// The label the failure was reported under (e.g. `"bash probe"`).
    pub fn label(&self) -> &str {
        &self.label
    }

    pub fn termination(&self) -> Termination {
        self.termination
    }

    pub fn exit_code(&self) -> Option<i32> {
        self.exit_code
    }

    /// Raw captured stdout. Not included in `Display`; the caller decides
    /// what is safe to expose.
    pub fn stdout(&self) -> &[u8] {
        &self.stdout
    }

    /// Raw captured stderr. Not included in `Display`.
    pub fn stderr(&self) -> &[u8] {
        &self.stderr
    }
}

/// Structured provider-side failure detail. Serializable so it crosses the
/// JSON-RPC boundary without losing structure.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[non_exhaustive]
pub struct ProviderError {
    pub provider:  ProviderKind,
    /// Provider-specific machine-readable code, when one exists.
    pub code:      Option<String>,
    pub message:   String,
    /// Whether the provider believes a retry may succeed.
    pub retryable: bool,
    /// Additional provider-specific structured detail.
    pub detail:    Option<serde_json::Value>,
    /// The in-process infrastructure cause. The JSON-RPC projection carries
    /// its rendered chain through [`crate::ErrorReport`] instead.
    #[serde(skip)]
    source:        Option<Box<OpaqueSource>>,
}

impl fmt::Display for ProviderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} error", self.provider)?;
        if let Some(code) = &self.code {
            write!(f, " [{code}]")?;
        }
        write!(f, ": {}", self.message)
    }
}

impl StdError for ProviderError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        self.source
            .as_ref()
            .map(|source| source.0.as_ref() as &(dyn StdError + 'static))
    }
}

impl ProviderError {
    pub fn new(provider: ProviderKind, message: impl Into<String>) -> Self {
        Self {
            provider,
            code: None,
            message: message.into(),
            retryable: false,
            detail: None,
            source: None,
        }
    }

    /// Creates a provider failure while preserving its infrastructure cause
    /// without exposing the cause type in the public API.
    pub fn with_source<E>(provider: ProviderKind, message: impl Into<String>, source: E) -> Self
    where
        E: StdError + Send + Sync + 'static,
    {
        Self {
            provider,
            code: None,
            message: message.into(),
            retryable: false,
            detail: None,
            source: Some(Box::new(OpaqueSource(Arc::new(source)))),
        }
    }
}

/// Failure while exchanging requests, responses, or notifications with an
/// out-of-process provider.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct TransportError {
    pub context: String,
    source:      Option<Box<OpaqueSource>>,
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.context)
    }
}

impl StdError for TransportError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        self.source
            .as_ref()
            .map(|source| source.0.as_ref() as &(dyn StdError + 'static))
    }
}

impl TransportError {
    pub fn new(context: impl Into<String>) -> Self {
        Self {
            context: context.into(),
            source:  None,
        }
    }

    /// Creates a transport failure while preserving its infrastructure cause.
    pub fn with_source<E>(context: impl Into<String>, source: E) -> Self
    where
        E: StdError + Send + Sync + 'static,
    {
        Self {
            context: context.into(),
            source:  Some(Box::new(OpaqueSource(Arc::new(source)))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsupported_names_the_capability() {
        let error = Error::unsupported(Capability::LifecyclePause);
        assert_eq!(
            error.to_string(),
            "capability lifecycle.pause is not supported by this provider"
        );
    }

    #[test]
    fn provider_errors_preserve_in_process_sources() {
        let provider = ProviderKind::try_new("test").expect("static provider kind is valid");
        let error = Error::Provider(ProviderError::with_source(
            provider,
            "listing sandboxes",
            io::Error::new(io::ErrorKind::ConnectionReset, "daemon disconnected"),
        ));

        let source = error.source().expect("provider error has a source");
        assert_eq!(source.to_string(), "daemon disconnected");
    }

    #[test]
    fn exec_failure_display_omits_raw_output() {
        let failure = ExecFailure::new(
            "bash probe",
            Termination::Exited,
            Some(1),
            b"secret stdout".to_vec(),
            b"secret stderr".to_vec(),
        );
        let rendered = failure.to_string();
        assert!(
            !rendered.contains("secret"),
            "raw output must stay behind accessors: {rendered}"
        );
        assert_eq!(failure.stdout(), b"secret stdout");
    }

    #[test]
    fn exec_failure_display_carries_a_static_hint_only() {
        let failure = ExecFailure::new(
            "git clone",
            Termination::Exited,
            Some(128),
            Vec::new(),
            b"fatal: could not resolve host: github.com/secret-org".to_vec(),
        );
        let rendered = failure.to_string();
        assert!(rendered.contains("hint: network failure"), "{rendered}");
        // The hint is classification, never quoted stderr.
        assert!(!rendered.contains("secret-org"), "{rendered}");
    }
}
