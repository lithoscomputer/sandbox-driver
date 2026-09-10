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

    /// A git operation failed, classified by what the remote or the
    /// working tree said so callers decide about retries and reporting
    /// without parsing git output themselves.
    #[error(transparent)]
    Git(#[from] GitFailure),

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
    /// Only provider-agnostic classes live here; git operations carry
    /// their classification in [`GitFailure`].
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

/// Why a git operation failed, read from what the remote or the working
/// tree reported.
///
/// The classes are the decisions a caller makes: whether waiting and
/// retrying can help, whether a different credential can, or whether the
/// request itself was wrong. Message matching lives here, once, so every
/// provider and both transports classify the same way.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum GitFailureKind {
    /// The remote rejected the supplied credential or hid the repository
    /// from it. GitHub answers `Repository not found.` for a private
    /// repository the credential cannot see and rejects a just-minted
    /// token until it has replicated, so the same shape covers a bad
    /// credential and one that is not visible yet; the caller knows
    /// which it holds.
    AuthRejected,
    /// The remote could not be reached or failed on its side. Retrying
    /// after a pause can succeed.
    RemoteUnavailable,
    /// The requested branch, tag, or commit does not exist at the remote.
    RefNotFound,
    /// Git needed a credential that was not supplied, or the remote
    /// denied access in a way no wait resolves (an SSH key it does not
    /// know, a user without permission).
    AccessDenied,
    /// The clone target already exists.
    TargetExists,
    /// The output matched no known class.
    Unclassified,
}

/// Message fragments that mean the operation failed on infrastructure.
const REMOTE_UNAVAILABLE_HINTS: &[&str] = &[
    "could not resolve host",
    "temporary failure in name resolution",
    "connection refused",
    "connection reset",
    "connection timed out",
    "timed out",
    "network is unreachable",
    "no route to host",
    "tls handshake",
    "early eof",
    "rpc failed",
    "unexpected disconnect",
    "the remote end hung up unexpectedly",
    "index-pack failed",
    "service unavailable",
    "gateway timeout",
    "too many requests",
    "rate limit",
];

/// Message fragments GitHub uses when a credential is rejected or not
/// yet visible; git over HTTP and libgit2 spell the status differently.
const AUTH_REJECTED_HINTS: &[&str] = &[
    "repository not found",
    "authentication failed",
    "invalid username or password",
    "bad credentials",
    "the requested url returned error: 401",
    "the requested url returned error: 403",
    "the requested url returned error: 404",
    "unexpected http status code: 401",
    "unexpected http status code: 403",
    "unexpected http status code: 404",
];

const REF_NOT_FOUND_HINTS: &[&str] = &[
    "couldn't find remote ref",
    "could not find remote branch",
    "not our ref",
    "unadvertised object",
    "reference is not a tree",
    "did not match any file(s) known to git",
    "unknown revision or path not in the working tree",
];

impl GitFailureKind {
    /// Classifies a failed git command by its output. stderr is read
    /// first; stdout only when stderr matches nothing.
    #[must_use]
    pub fn from_output(stderr: &[u8], stdout: &[u8]) -> Self {
        let by_stderr = Self::from_message(&String::from_utf8_lossy(stderr));
        if by_stderr == Self::Unclassified {
            Self::from_message(&String::from_utf8_lossy(stdout))
        } else {
            by_stderr
        }
    }

    /// Classifies a rendered git failure message.
    #[must_use]
    pub fn from_message(message: &str) -> Self {
        let lower = message.to_ascii_lowercase();
        if REMOTE_UNAVAILABLE_HINTS
            .iter()
            .any(|hint| lower.contains(hint))
        {
            return Self::RemoteUnavailable;
        }
        if AUTH_REJECTED_HINTS.iter().any(|hint| lower.contains(hint)) {
            return Self::AuthRejected;
        }
        if lower.contains("could not read username")
            || lower.contains("terminal prompts disabled")
            || lower.contains("permission denied")
            || (lower.contains("permission to") && lower.contains("denied"))
        {
            return Self::AccessDenied;
        }
        if lower.contains("destination path") && lower.contains("already exists") {
            return Self::TargetExists;
        }
        if REF_NOT_FOUND_HINTS.iter().any(|hint| lower.contains(hint))
            || (lower.contains("remote branch") && lower.contains("not found"))
        {
            return Self::RefNotFound;
        }
        Self::Unclassified
    }

    /// Whether a retry after a pause can succeed with the same request.
    #[must_use]
    pub fn is_transient(self) -> bool {
        matches!(self, Self::RemoteUnavailable)
    }

    fn describe(self) -> &'static str {
        match self {
            Self::AuthRejected => "the remote rejected the credential or hid the repository",
            Self::RemoteUnavailable => "the remote could not be reached",
            Self::RefNotFound => "the requested revision does not exist at the remote",
            Self::AccessDenied => "access was denied",
            Self::TargetExists => "the clone target already exists",
            Self::Unclassified => "unclassified failure",
        }
    }
}

/// A failed git operation with its classification and the evidence it was
/// read from: the command's output when git ran inside the sandbox, or
/// the provider's reported failure when a native clone ran it.
///
/// `Display` carries the operation and the class only; raw output stays
/// behind [`GitFailure::output`] so the caller controls exposure and
/// redaction, as with [`ExecFailure`].
#[derive(Debug)]
pub struct GitFailure {
    operation: String,
    kind:      GitFailureKind,
    // Boxed so the error enum stays small on every `Result`.
    output:    Option<Box<ExecFailure>>,
    provider:  Option<Box<ProviderError>>,
}

impl fmt::Display for GitFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} failed: {}", self.operation, self.kind.describe())?;
        if let Some(output) = &self.output {
            write!(f, " (exit code {:?})", output.exit_code())?;
        }
        Ok(())
    }
}

impl StdError for GitFailure {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        self.provider
            .as_deref()
            .map(|provider| provider as &(dyn StdError + 'static))
    }
}

impl GitFailure {
    /// A git command that ran inside the sandbox and failed; the class is
    /// read from its output.
    pub fn from_command(operation: impl Into<String>, output: ExecFailure) -> Self {
        Self {
            operation: operation.into(),
            kind:      GitFailureKind::from_output(output.stderr(), output.stdout()),
            output:    Some(Box::new(output)),
            provider:  None,
        }
    }

    /// A provider's native git operation that failed; the class is read
    /// from the provider's message, and a failure the provider marks
    /// retryable that matches nothing else is treated as the remote
    /// being unavailable.
    pub fn from_provider(operation: impl Into<String>, provider: ProviderError) -> Self {
        let mut kind = GitFailureKind::from_message(&provider.message);
        if kind == GitFailureKind::Unclassified && provider.retryable {
            kind = GitFailureKind::RemoteUnavailable;
        }
        Self {
            operation: operation.into(),
            kind,
            output: None,
            provider: Some(Box::new(provider)),
        }
    }

    /// Builds a failure with an explicit class, for a provider that
    /// already knows why the operation failed.
    pub fn classified(
        operation: impl Into<String>,
        kind: GitFailureKind,
        provider: Option<ProviderError>,
    ) -> Self {
        Self {
            operation: operation.into(),
            kind,
            output: None,
            provider: provider.map(Box::new),
        }
    }

    /// Attaches the command output a reconstructed failure was read from.
    #[must_use]
    pub fn with_output(mut self, output: ExecFailure) -> Self {
        self.output = Some(Box::new(output));
        self
    }

    /// The operation that failed (`"git clone"`, `"git push"`).
    pub fn operation(&self) -> &str {
        &self.operation
    }

    pub fn kind(&self) -> GitFailureKind {
        self.kind
    }

    /// The failed command, with its raw output, when git ran inside the
    /// sandbox. Not included in `Display`.
    pub fn output(&self) -> Option<&ExecFailure> {
        self.output.as_deref()
    }

    /// The provider's reported failure, when a native operation ran it.
    pub fn provider(&self) -> Option<&ProviderError> {
        self.provider.as_deref()
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
    fn git_failures_classify_output_without_exposing_it() {
        let cases: &[(&str, GitFailureKind)] = &[
            (
                "fatal: could not resolve host: github.com",
                GitFailureKind::RemoteUnavailable,
            ),
            (
                "error: RPC failed; curl 56 Recv failure",
                GitFailureKind::RemoteUnavailable,
            ),
            (
                "remote: Repository not found.\nfatal: repository 'https://github.com/o/secret.git/' not found",
                GitFailureKind::AuthRejected,
            ),
            (
                "fatal: Authentication failed for 'https://github.com/o/r.git/'",
                GitFailureKind::AuthRejected,
            ),
            (
                "fatal: could not read Username for 'https://github.com': terminal prompts disabled",
                GitFailureKind::AccessDenied,
            ),
            (
                "git@github.com: Permission denied (publickey).",
                GitFailureKind::AccessDenied,
            ),
            (
                "fatal: destination path 'repo' already exists and is not an empty directory.",
                GitFailureKind::TargetExists,
            ),
            (
                "fatal: couldn't find remote ref refs/tags/v9.9.9",
                GitFailureKind::RefNotFound,
            ),
            (
                "fatal: Remote branch nope not found in upstream origin",
                GitFailureKind::RefNotFound,
            ),
            (
                "error: Server does not allow request for unadvertised object 0123",
                GitFailureKind::RefNotFound,
            ),
            (
                "fatal: remote error: upload-pack: not our ref 0123",
                GitFailureKind::RefNotFound,
            ),
            ("something else entirely", GitFailureKind::Unclassified),
        ];
        for (stderr, expected) in cases {
            let failure = GitFailure::from_command(
                "git clone",
                ExecFailure::new(
                    "git clone",
                    Termination::Exited,
                    Some(128),
                    Vec::new(),
                    stderr.as_bytes().to_vec(),
                ),
            );
            assert_eq!(failure.kind(), *expected, "{stderr}");
            let rendered = failure.to_string();
            assert!(
                !rendered.contains("github.com"),
                "raw output must stay behind accessors: {rendered}"
            );
        }
    }

    #[test]
    fn git_failures_read_stdout_when_stderr_says_nothing() {
        let failure = GitFailure::from_command(
            "git push",
            ExecFailure::new(
                "git push",
                Termination::Exited,
                Some(1),
                b"remote: Bad credentials".to_vec(),
                b"".to_vec(),
            ),
        );
        assert_eq!(failure.kind(), GitFailureKind::AuthRejected);
    }

    #[test]
    fn provider_git_failures_classify_the_message_and_honor_retryable() {
        let provider = ProviderKind::try_new("test").expect("static provider kind is valid");
        let failure = GitFailure::from_provider(
            "git clone",
            ProviderError::new(provider.clone(), "authentication failed"),
        );
        assert_eq!(failure.kind(), GitFailureKind::AuthRejected);

        let mut retryable = ProviderError::new(provider.clone(), "toolbox unavailable");
        retryable.retryable = true;
        let failure = GitFailure::from_provider("git clone", retryable);
        assert_eq!(failure.kind(), GitFailureKind::RemoteUnavailable);
        assert!(failure.kind().is_transient());

        let failure =
            GitFailure::from_provider("git clone", ProviderError::new(provider, "no idea"));
        assert_eq!(failure.kind(), GitFailureKind::Unclassified);
        assert!(!failure.kind().is_transient());
        assert!(
            failure.source().is_some(),
            "the provider failure stays in the chain"
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
