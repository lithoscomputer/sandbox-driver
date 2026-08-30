use std::collections::BTreeMap;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::sync::CancellationToken;

use crate::capabilities::Capability;
use crate::error::{Error, Result};

/// Command execution inside a sandbox.
///
/// # The Bash contract (normative)
///
/// `command` is Bash source, evaluated as `bash -c <command>`, non-login.
/// Implementations select the interpreter, never its options: no `errexit`,
/// no `pipefail`, no POSIX mode, never a fallback to `sh`, never a
/// provider's ambient shell. A caller wanting other semantics writes them
/// into the command. `BASH_ENV` is stripped before every invocation.
/// Buffered and streaming execution must not differ in interpreter or
/// options. The [`crate::run_bash_probe`] helper verifies this contract and
/// belongs in every provider's conformance run.
#[async_trait]
pub trait Exec: Send + Sync {
    /// Runs a command to completion, buffering output.
    async fn run(&self, spec: &ExecSpec) -> Result<ExecResult>;

    /// Runs a command, delivering output through `controls.sink` as it
    /// arrives. Providers that cannot stream fall back to buffered
    /// execution, replay the output through the sink, and report
    /// `live_streaming: false`.
    ///
    /// Control contracts: cancellation resolves the call normally with
    /// [`Termination::Cancelled`] after a best-effort process-group kill.
    /// The sink is awaited per chunk — a slow consumer backpressures the
    /// read loop. Output beyond `controls.retained_output_limit` is still
    /// drained (and counted in [`CaptureStats::omitted_bytes`]), never left
    /// to block the process. A sink error cancels the execution.
    ///
    /// A provider that does not support stdin or cancellation must reject
    /// a call that supplies them with [`Error::Unsupported`]
    /// (`exec.stdin` / `exec.cancel`) — never run the command with the
    /// input silently dropped. Capability preflight is the supported way
    /// to avoid the error.
    async fn run_streaming(
        &self,
        spec: &ExecSpec,
        controls: ExecControls,
    ) -> Result<ExecStreamingResult>;

    /// Spawns a long-lived bidirectional stdio process (ACP backends).
    ///
    /// Capability-gated on `exec.stdio_process`; the default returns
    /// [`Error::Unsupported`].
    async fn spawn_stdio(&self, spec: &SpawnSpec) -> Result<StdioProcess> {
        let _ = spec;
        Err(Error::unsupported(Capability::ExecStdioProcess))
    }
}

/// Serializable execution request — exactly what crosses the JSON-RPC
/// boundary. Process-local control objects travel in [`ExecControls`].
#[derive(Clone, Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub struct ExecSpec {
    /// Bash source; see the trait-level contract.
    pub command:     String,
    pub timeout:     Option<Duration>,
    pub working_dir: Option<String>,
    pub env:         BTreeMap<String, String>,
    /// Written to the process then closed for EOF. A broken pipe while
    /// writing (the `head -1` case) is not an error.
    pub stdin:       Option<Vec<u8>>,
}

impl ExecSpec {
    pub fn new(command: impl Into<String>) -> Self {
        Self {
            command:     command.into(),
            timeout:     None,
            working_dir: None,
            env:         BTreeMap::new(),
            stdin:       None,
        }
    }

    #[must_use]
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    #[must_use]
    pub fn working_dir(mut self, dir: impl Into<String>) -> Self {
        self.working_dir = Some(dir.into());
        self
    }

    #[must_use]
    pub fn env_var(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.env.insert(key.into(), value.into());
        self
    }

    #[must_use]
    pub fn stdin(mut self, bytes: Vec<u8>) -> Self {
        self.stdin = Some(bytes);
        self
    }
}

/// Which output stream a chunk belongs to.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutputStream {
    Stdout,
    Stderr,
}

/// Async output sink for streaming execution. Awaited per chunk; returning
/// an error cancels the execution.
pub type OutputSink = Arc<
    dyn Fn(OutputStream, Vec<u8>) -> Pin<Box<dyn Future<Output = Result<()>> + Send>> + Send + Sync,
>;

/// Process-local controls for [`Exec::run_streaming`]. Never serialized;
/// on the wire these map to negotiated execution IDs.
#[derive(Clone, Default)]
pub struct ExecControls {
    pub cancel:                Option<CancellationToken>,
    pub sink:                  Option<OutputSink>,
    /// Retention cap for the buffered copy in the result (head + tail);
    /// output beyond it is drained and counted, not kept.
    pub retained_output_limit: Option<usize>,
}

impl fmt::Debug for ExecControls {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExecControls")
            .field("cancel", &self.cancel.is_some())
            .field("sink", &self.sink.is_some())
            .field("retained_output_limit", &self.retained_output_limit)
            .finish()
    }
}

/// How a command ended.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Termination {
    Exited,
    TimedOut,
    Cancelled,
    Killed,
    #[serde(other)]
    Unknown,
}

/// Result of a buffered command run. Output is bytes: sandbox output is
/// not guaranteed UTF-8.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub struct ExecResult {
    pub stdout:      Vec<u8>,
    pub stderr:      Vec<u8>,
    /// Meaningful only when `termination` is [`Termination::Exited`].
    /// A timed-out or cancelled run may still carry a code the provider
    /// happened to observe (a trapped SIGTERM exiting 0, a kill
    /// wrapper's 143) — never treat `Some(0)` alone as success; use
    /// [`ExecResult::success`], which checks the termination.
    pub exit_code:   Option<i32>,
    pub termination: Termination,
    pub duration:    Duration,
}

impl ExecResult {
    pub fn new(termination: Termination, exit_code: Option<i32>, duration: Duration) -> Self {
        Self {
            stdout: Vec::new(),
            stderr: Vec::new(),
            exit_code,
            termination,
            duration,
        }
    }

    /// Stdout decoded lossily for display.
    pub fn stdout_lossy(&self) -> String {
        String::from_utf8_lossy(&self.stdout).into_owned()
    }

    /// Stderr decoded lossily for display.
    pub fn stderr_lossy(&self) -> String {
        String::from_utf8_lossy(&self.stderr).into_owned()
    }

    /// Whether the command exited on its own with code 0.
    pub fn success(&self) -> bool {
        self.termination == Termination::Exited && self.exit_code == Some(0)
    }
}

/// Retention accounting for one captured stream.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct CaptureStats {
    pub observed_bytes: usize,
    pub retained_bytes: usize,
    pub omitted_bytes:  usize,
}

impl CaptureStats {
    /// Accounting for a fully retained buffer: everything observed was
    /// kept.
    pub fn complete(bytes: usize) -> Self {
        Self {
            observed_bytes: bytes,
            retained_bytes: bytes,
            omitted_bytes:  0,
        }
    }
}

/// Result of a streaming run, with honesty flags: degradations (combined
/// output, buffered replay) are reported, not hidden.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub struct ExecStreamingResult {
    pub result:            ExecResult,
    /// Stdout and stderr were genuinely separate streams.
    pub streams_separated: bool,
    /// Output was delivered while the command ran (vs. replayed after).
    pub live_streaming:    bool,
    pub stdout_capture:    CaptureStats,
    pub stderr_capture:    CaptureStats,
}

impl ExecStreamingResult {
    /// Wraps a buffered result with the honesty flags at their degraded
    /// defaults (`streams_separated: false`, `live_streaming: false`);
    /// providers set the flags they actually deliver. Capture stats
    /// start as fully-retained accounting of the wrapped buffers — a
    /// provider that truncated at the source overrides them — so
    /// `observed_bytes: 0` can never sit beside non-empty output.
    pub fn new(result: ExecResult) -> Self {
        let stdout_capture = CaptureStats::complete(result.stdout.len());
        let stderr_capture = CaptureStats::complete(result.stderr.len());
        Self {
            result,
            streams_separated: false,
            live_streaming: false,
            stdout_capture,
            stderr_capture,
        }
    }
}

/// Serializable spawn request for [`Exec::spawn_stdio`]. The command is
/// Bash source under the same contract as [`ExecSpec::command`].
#[derive(Clone, Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub struct SpawnSpec {
    pub command:     String,
    pub working_dir: Option<String>,
    pub env:         BTreeMap<String, String>,
}

impl SpawnSpec {
    pub fn new(command: impl Into<String>) -> Self {
        Self {
            command:     command.into(),
            working_dir: None,
            env:         BTreeMap::new(),
        }
    }
}

/// A live bidirectional stdio process.
///
/// Stderr is not a stream: it is a bounded rolling tail intended for
/// diagnostics on unexpected exit.
///
/// There is no cancel token: the handle is the one lifecycle channel.
/// A caller with a `CancellationToken` wires it to
/// [`StdioProcessHandle::terminate`] itself:
///
/// ```ignore
/// tokio::select! {
///     () = token.cancelled() => process.handle.terminate().await,
///     outcome = process.handle.wait() => { /* natural exit */ }
/// }
/// ```
///
/// Dropping the handle does **not** stop the process — it runs to its
/// natural exit — so a caller that abandons the handle without
/// `terminate` leaks the workload.
pub struct StdioProcess {
    pub stdin:       Pin<Box<dyn AsyncWrite + Send>>,
    pub stdout:      Pin<Box<dyn AsyncRead + Send>>,
    pub stderr_tail: StderrTail,
    pub handle:      Box<dyn StdioProcessHandle>,
}

impl fmt::Debug for StdioProcess {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StdioProcess").finish_non_exhaustive()
    }
}

/// Control handle for a spawned stdio process.
#[async_trait]
pub trait StdioProcessHandle: Send + Sync {
    /// Requests termination (best-effort process-group kill).
    async fn terminate(&self);

    /// Waits for the process to end.
    async fn wait(&self) -> (Termination, Option<i32>);
}

const DEFAULT_STDERR_TAIL_BYTES: usize = 8 * 1024;

/// Bounded rolling tail of stderr output.
#[derive(Clone, Debug)]
pub struct StderrTail {
    inner: Arc<Mutex<TailBuffer>>,
}

#[derive(Debug)]
struct TailBuffer {
    max_bytes: usize,
    bytes:     Vec<u8>,
    truncated: bool,
}

impl StderrTail {
    pub fn new(max_bytes: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(TailBuffer {
                max_bytes,
                bytes: Vec::new(),
                truncated: false,
            })),
        }
    }

    /// Appends bytes, keeping only the newest `max_bytes`.
    pub fn push(&self, chunk: &[u8]) {
        let mut tail = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        tail.bytes.extend_from_slice(chunk);
        let max = tail.max_bytes;
        if tail.bytes.len() > max {
            let excess = tail.bytes.len() - max;
            tail.bytes.drain(..excess);
            tail.truncated = true;
        }
    }

    /// The retained tail decoded lossily, prefixed with an ellipsis when
    /// earlier output was dropped.
    pub fn to_string_lossy(&self) -> String {
        let tail = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        let text = String::from_utf8_lossy(&tail.bytes);
        if tail.truncated {
            format!("…{text}")
        } else {
            text.into_owned()
        }
    }
}

impl Default for StderrTail {
    fn default() -> Self {
        Self::new(DEFAULT_STDERR_TAIL_BYTES)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stderr_tail_keeps_only_newest_bytes() {
        let tail = StderrTail::new(8);
        tail.push(b"0123456789");
        assert_eq!(tail.to_string_lossy(), "…23456789");
        tail.push(b"AB");
        assert_eq!(tail.to_string_lossy(), "…456789AB");
    }

    #[test]
    fn exec_result_success_requires_clean_exit() {
        let ok = ExecResult::new(Termination::Exited, Some(0), Duration::from_millis(1));
        assert!(ok.success());
        let cancelled = ExecResult::new(Termination::Cancelled, Some(0), Duration::from_millis(1));
        assert!(!cancelled.success());
    }
}
