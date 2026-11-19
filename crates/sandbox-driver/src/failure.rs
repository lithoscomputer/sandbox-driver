//! What a library helper reports when a command it ran in a sandbox did not
//! do its job. A command that exits nonzero is an [`ExecOutcome`], not an
//! [`Error`], and `Error` carries no command output, so the helpers built on
//! [`run_captured`](super::run_captured) fail with these types instead.

use std::error::Error as StdError;
use std::fmt;
use std::fmt::Write as _;
use std::time::Duration;

use super::{Captured, CapturedOutput, Error, ExecOutcome, Termination};

/// How much of each stream [`CommandFailure::new`] keeps.
const TAIL_BYTES: usize = 8 * 1024;

/// The newest bytes of one stream of a command.
#[derive(Clone, Default, Eq, PartialEq)]
pub struct OutputTail {
    pub bytes:         Vec<u8>,
    /// Bytes the command wrote to this stream before `bytes`.
    pub omitted_bytes: u64,
}

impl OutputTail {
    fn of(output: &CapturedOutput) -> Self {
        let (bytes, omitted_bytes) = output.newest(TAIL_BYTES);
        Self {
            bytes: bytes.to_vec(),
            omitted_bytes,
        }
    }

    fn is_empty(&self) -> bool {
        self.bytes.is_empty() && self.omitted_bytes == 0
    }
}

// Command output can carry credentials, as `ExecSpec::argv` can.
impl fmt::Debug for OutputTail {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OutputTail")
            .field("retained_bytes", &self.bytes.len())
            .field("omitted_bytes", &self.omitted_bytes)
            .finish()
    }
}

/// A command that ran and left its caller without a result, kept with the
/// end of what it wrote.
///
/// `Display` says what the command was for and how it ended. It never
/// includes output, so it is safe wherever an [`Error`] message is.
/// [`Self::display_for_log`] adds the output.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandFailure {
    /// What the command was for, such as `stat`; never the command itself.
    pub context:     String,
    pub outcome:     ExecOutcome,
    pub stdout_tail: OutputTail,
    pub stderr_tail: OutputTail,
    pub duration:    Duration,
}

impl CommandFailure {
    /// The failure a finished command describes, keeping the last 8 KiB of
    /// each stream.
    pub fn new(context: impl Into<String>, captured: &Captured) -> Self {
        Self {
            context:     context.into(),
            outcome:     captured.outcome.clone(),
            stdout_tail: OutputTail::of(&captured.stdout),
            stderr_tail: OutputTail::of(&captured.stderr),
            duration:    captured.duration,
        }
    }

    /// `Display`, then each stream's tail under a header that gives its
    /// size, stderr first. A stream the command wrote nothing to is left
    /// out.
    ///
    /// The result holds raw command output, which can carry credentials:
    /// pass it through your redaction before it leaves the process.
    pub fn display_for_log(&self) -> String {
        let mut rendered = self.to_string();
        for (stream, tail) in [("stderr", &self.stderr_tail), ("stdout", &self.stdout_tail)] {
            if tail.is_empty() {
                continue;
            }
            let _ = write!(
                rendered,
                "\n--- {stream} (bytes={}, omitted_bytes={}) ---\n{}",
                tail.bytes.len(),
                tail.omitted_bytes,
                String::from_utf8_lossy(&tail.bytes)
            );
        }
        rendered
    }
}

impl fmt::Display for CommandFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} failed: the command ", self.context)?;
        match (self.outcome.termination, self.outcome.exit_code) {
            (Termination::Exited, Some(code)) => write!(f, "exited with code {code}")?,
            (Termination::Exited, None) => f.write_str("exited without a code")?,
            (Termination::TimedOut, _) => f.write_str("timed out")?,
            (Termination::Terminated, _) => f.write_str("was terminated")?,
            (Termination::Killed, _) => f.write_str("was killed")?,
            (Termination::Lost, _) => f.write_str("ended with an unknown outcome")?,
        }
        write!(f, " after {} ms", self.duration.as_millis())
    }
}

impl StdError for CommandFailure {}

/// Why a helper that runs a command in a sandbox failed.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum CommandError {
    /// The sandbox refused or lost the exec, or the request was invalid. The
    /// command may not have run.
    #[error(transparent)]
    Sandbox(#[from] Error),
    /// The command ran and did not succeed.
    #[error(transparent)]
    Failed(Box<CommandFailure>),
    /// The command exited with code zero, but its output was incomplete or
    /// not in the form the helper reads.
    #[error("{}: the command's output could not be read", .0.context)]
    UnexpectedOutput(Box<CommandFailure>),
}

// A failure is boxed so that the error stays small on the success path.
impl From<CommandFailure> for CommandError {
    fn from(failure: CommandFailure) -> Self {
        Self::Failed(Box::new(failure))
    }
}

impl CommandError {
    /// The command behind this error, when one ran.
    pub fn failure(&self) -> Option<&CommandFailure> {
        match self {
            Self::Sandbox(_) => None,
            Self::Failed(failure) | Self::UnexpectedOutput(failure) => Some(failure),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exited(exit_code: i32, stdout: &[u8], stderr: &[u8]) -> Captured {
        Captured::ended(Termination::Exited, Some(exit_code), stdout, stderr)
    }

    #[test]
    fn display_never_includes_output_and_the_log_form_adds_each_written_stream() {
        let secret = "ghs_notarealtoken";
        let failure = CommandFailure::new(
            "git fetch",
            &exited(128, b"", format!("fatal: bad token {secret}\n").as_bytes()),
        );
        assert_eq!(
            failure.to_string(),
            "git fetch failed: the command exited with code 128 after 1500 ms"
        );
        assert!(!format!("{failure:?}").contains(secret));
        // stdout was empty, so only stderr gets a section.
        assert_eq!(
            failure.display_for_log(),
            format!(
                "git fetch failed: the command exited with code 128 after 1500 ms\n--- stderr \
                 (bytes=35, omitted_bytes=0) ---\nfatal: bad token {secret}\n"
            )
        );
    }

    #[test]
    fn a_failure_keeps_only_the_end_of_a_long_stream_and_counts_the_rest() {
        let mut bytes = vec![b'a'; 100];
        bytes.extend(vec![b'z'; TAIL_BYTES]);
        let failure = CommandFailure::new("build", &exited(1, b"", &bytes));
        assert_eq!(failure.stderr_tail.bytes, vec![b'z'; TAIL_BYTES]);
        assert_eq!(failure.stderr_tail.omitted_bytes, 100);
    }

    #[test]
    fn an_error_names_its_command_only_when_one_ran() {
        let failure = CommandFailure::new("stat", &exited(0, b"??", b""));
        let unreadable = CommandError::UnexpectedOutput(Box::new(failure.clone()));
        assert_eq!(
            unreadable.to_string(),
            "stat: the command's output could not be read"
        );
        assert_eq!(unreadable.failure(), Some(&failure));
        let refused = CommandError::from(Error::Busy {
            message: "stopping".into(),
        });
        assert_eq!(refused.failure(), None);
        assert_eq!(refused.to_string(), "sandbox busy: stopping");
        // A failed command reads the same inside the error as on its own.
        assert_eq!(
            CommandError::from(failure.clone()).to_string(),
            failure.to_string()
        );
    }
}
