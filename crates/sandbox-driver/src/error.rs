use std::io;
use std::result::Result as StdResult;
use std::time::Duration;

use crate::capabilities::Capability;
use crate::event::LifecycleAction;
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
    Checkpoint,
    /// A plugin binary, in discovery errors.
    Plugin,
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
        action:  LifecycleAction,
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

    /// A command inside the sandbox failed in a way the caller did not run
    /// it to observe (probe failures, derived-operation failures).
    #[error(transparent)]
    Exec(#[from] ExecFailure),

    #[error(transparent)]
    Provider(#[from] ProviderError),

    /// Local I/O failure (uploads, downloads, spawning).
    #[error("{context}")]
    Io {
        context: String,
        #[source]
        source:  io::Error,
    },
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
#[derive(Debug, thiserror::Error)]
#[error("authentication with {provider} failed: {reason}")]
#[non_exhaustive]
pub struct AuthError {
    pub provider: ProviderKind,
    pub reason:   String,
}

impl AuthError {
    pub fn new(provider: ProviderKind, reason: impl Into<String>) -> Self {
        Self {
            provider,
            reason: reason.into(),
        }
    }
}

/// A failed command execution, with bounded classified metadata in
/// `Display` and raw output behind explicit accessors so callers control
/// exposure. Secret redaction is the caller's responsibility.
#[derive(Debug, thiserror::Error)]
#[error("command {label:?} failed ({termination:?}, exit code {exit_code:?})")]
pub struct ExecFailure {
    label:       String,
    termination: Termination,
    exit_code:   Option<i32>,
    stdout:      Vec<u8>,
    stderr:      Vec<u8>,
}

impl ExecFailure {
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
        }
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
#[derive(Debug, thiserror::Error, serde::Serialize, serde::Deserialize)]
#[error("{provider} error{}: {message}", code.as_deref().map(|c| format!(" [{c}]")).unwrap_or_default())]
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
}

impl ProviderError {
    pub fn new(provider: ProviderKind, message: impl Into<String>) -> Self {
        Self {
            provider,
            code: None,
            message: message.into(),
            retryable: false,
            detail: None,
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
}
