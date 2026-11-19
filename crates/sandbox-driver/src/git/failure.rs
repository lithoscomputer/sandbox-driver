//! Why a git operation failed, and what a git helper fails with.

use std::error::Error as StdError;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::{Captured, CommandFailure, Error, Termination};

/// Why a git operation failed, read from what the remote or the working
/// tree reported.
///
/// The classes are the decisions a caller makes: whether waiting and
/// retrying can help, whether a different credential can, or whether the
/// request itself was wrong. Message matching lives here, once, so git that
/// ran in a sandbox and git that ran beside it classify the same way.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
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
    /// The requested branch, tag, or commit does not exist.
    RefNotFound,
    /// Git needed a credential that was not supplied, or the remote
    /// denied access in a way no wait resolves (an SSH key it does not
    /// know, a user without permission).
    AccessDenied,
    /// The clone target already exists.
    TargetExists,
    /// The workload has no usable `git` executable: the command could not
    /// be found (exit 127) or could not run (exit 126). No retry or
    /// credential helps.
    GitUnavailable,
    /// The output matched no known class. Also what an older reader makes
    /// of a class it does not know.
    #[serde(other)]
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
            Self::RefNotFound => "the requested revision does not exist",
            Self::AccessDenied => "access was denied",
            Self::TargetExists => "the clone target already exists",
            Self::GitUnavailable => "the workload has no usable git executable",
            Self::Unclassified => "unclassified failure",
        }
    }
}

/// A failed git operation with its class and, when git ran in a sandbox,
/// the command it was read from.
///
/// `Display` gives the operation and the class only, so it is safe wherever
/// an [`Error`] message is. [`Self::display_for_log`] adds the output.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitFailure {
    /// The operation that failed, such as `git log`.
    pub operation: String,
    pub kind:      GitFailureKind,
    /// The command with the end of its output; `None` for a failure that
    /// was classified from a message.
    pub command:   Option<CommandFailure>,
}

impl GitFailure {
    /// The failure of a git command that ran in a sandbox. Its class is
    /// read from all the output that was captured. Exit codes 127 and 126
    /// are the shell saying `git` itself could not be found or run, so they
    /// classify before the output is read.
    pub fn new(operation: impl Into<String>, captured: &Captured) -> Self {
        let operation = operation.into();
        let kind = match captured.outcome.exit_code {
            Some(126 | 127) => GitFailureKind::GitUnavailable,
            _ => GitFailureKind::from_output(&captured.stderr.bytes, &captured.stdout.bytes),
        };
        Self {
            command: Some(CommandFailure::new(operation.clone(), captured)),
            operation,
            kind,
        }
    }

    /// A failure whose class is already known, for git that ran outside a
    /// sandbox: classify its message with [`GitFailureKind::from_message`].
    pub fn classified(operation: impl Into<String>, kind: GitFailureKind) -> Self {
        Self {
            operation: operation.into(),
            kind,
            command: None,
        }
    }

    /// `Display`, then the command with the end of each stream it wrote.
    ///
    /// The result holds raw command output, which can carry credentials:
    /// pass it through your redaction before it leaves the process.
    pub fn display_for_log(&self) -> String {
        match &self.command {
            Some(command) => format!("{self}\n{}", command.display_for_log()),
            None => self.to_string(),
        }
    }
}

impl fmt::Display for GitFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let operation = &self.operation;
        let Some(command) = &self.command else {
            return write!(f, "{operation} failed: {}", self.kind.describe());
        };
        let ended_early = match command.outcome.termination {
            Termination::Exited => None,
            Termination::TimedOut => Some("timed out"),
            Termination::Terminated => Some("was terminated"),
            Termination::Killed => Some("was killed"),
            Termination::Lost => Some("ended with an unknown outcome"),
        };
        match (ended_early, command.outcome.exit_code) {
            (Some(how), _) => {
                write!(f, "{operation} {how}")?;
                match command.duration {
                    Some(duration) => write!(f, " after {} ms", duration.as_millis()),
                    None => Ok(()),
                }
            }
            (None, Some(code)) => write!(
                f,
                "{operation} failed: {} (exit code {code})",
                self.kind.describe()
            ),
            (None, None) => write!(f, "{operation} failed: {}", self.kind.describe()),
        }
    }
}

impl StdError for GitFailure {}

/// Why a git helper failed.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum GitError {
    /// The sandbox refused or lost the exec, or the request was invalid.
    /// Git may not have run.
    #[error(transparent)]
    Sandbox(#[from] Error),
    /// Git ran and did not succeed.
    #[error(transparent)]
    Failed(Box<GitFailure>),
    /// Git exited with code zero, but its output was incomplete or not in
    /// the form the helper reads.
    #[error("{}: git's output could not be read", .0.context)]
    UnexpectedOutput(Box<CommandFailure>),
}

// A failure is boxed so that the error stays small on the success path.
impl From<GitFailure> for GitError {
    fn from(failure: GitFailure) -> Self {
        Self::Failed(Box::new(failure))
    }
}

impl GitError {
    /// The class of a git failure; `None` when git did not fail.
    pub fn kind(&self) -> Option<GitFailureKind> {
        match self {
            Self::Failed(failure) => Some(failure.kind),
            Self::Sandbox(_) | Self::UnexpectedOutput(_) => None,
        }
    }

    /// The command behind this error, when one ran in a sandbox.
    pub fn command(&self) -> Option<&CommandFailure> {
        match self {
            Self::Sandbox(_) => None,
            Self::Failed(failure) => failure.command.as_ref(),
            Self::UnexpectedOutput(command) => Some(command),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ended(termination: Termination, exit_code: Option<i32>, stderr: &str) -> Captured {
        Captured::ended(termination, exit_code, b"", stderr.as_bytes())
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
                "fatal: ambiguous argument 'nope': unknown revision or path not in the working tree.",
                GitFailureKind::RefNotFound,
            ),
            ("something else entirely", GitFailureKind::Unclassified),
        ];
        for (stderr, expected) in cases {
            let failure =
                GitFailure::new("git clone", &ended(Termination::Exited, Some(128), stderr));
            assert_eq!(failure.kind, *expected, "{stderr}");
            let shown = failure.to_string();
            assert!(shown.starts_with("git clone failed: "), "{shown}");
            assert!(shown.ends_with("(exit code 128)"), "{shown}");
            assert!(!shown.contains("github.com"), "{shown}");
            assert!(failure.display_for_log().contains(stderr), "{stderr}");
        }
    }

    #[test]
    fn a_shell_that_cannot_run_git_classifies_before_its_message_is_read() {
        for code in [126, 127] {
            let captured = ended(Termination::Exited, Some(code), "git: Permission denied");
            assert_eq!(
                GitFailure::new("git log", &captured).kind,
                GitFailureKind::GitUnavailable
            );
        }
    }

    #[test]
    fn a_command_that_ended_early_says_how_and_a_message_only_failure_has_no_command() {
        let timed_out = GitFailure::new("git diff", &ended(Termination::TimedOut, None, ""));
        assert_eq!(timed_out.to_string(), "git diff timed out after 1500 ms");

        let classified = GitFailure::classified(
            "repository probe",
            GitFailureKind::from_message("fatal: unable to access: Connection refused"),
        );
        assert_eq!(classified.kind, GitFailureKind::RemoteUnavailable);
        assert!(classified.kind.is_transient());
        assert_eq!(
            classified.display_for_log(),
            "repository probe failed: the remote could not be reached"
        );
        let error = GitError::from(classified);
        assert_eq!(error.kind(), Some(GitFailureKind::RemoteUnavailable));
        assert_eq!(error.command(), None);
    }

    #[test]
    fn a_class_this_version_does_not_know_reads_as_unclassified() {
        assert_eq!(
            serde_json::from_str::<GitFailureKind>("\"quota_exceeded\"").ok(),
            Some(GitFailureKind::Unclassified)
        );
        assert_eq!(
            serde_json::to_string(&GitFailureKind::RefNotFound).ok(),
            Some("\"ref_not_found\"".to_owned())
        );
    }
}
