//! Output of a Docker exec or one-shot container: captured and sanitized
//! while it streams to the caller, and drained under the stop ladder
//! every Docker command shares.

use std::future;
use std::pin::pin;
use std::result::Result as StdResult;
use std::time::{Duration, Instant};

use bollard::container::LogOutput;
use bollard::errors::Error as DockerApiError;
use futures_util::{Stream, StreamExt};
use sandbox_driver::{
    ExecControls, ExecResult, ExecStreamingResult, OutputCaptureBuffer, OutputSanitization,
    OutputSanitizer, OutputSink, OutputStream, Result, Termination, stop_signal,
};
use tokio::time;
use tokio_util::sync::CancellationToken;

/// Grace period for draining output after a kill request. Must exceed
/// the exec watcher's poll interval.
pub(crate) const KILL_DRAIN_GRACE: Duration = Duration::from_secs(10);

/// How a running command is asked to stop. `Term` is sent once and the
/// command keeps draining; `Kill` ends it and starts the drain grace.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StopMode {
    /// SIGTERM the command, once.
    Term,
    /// SIGKILL the command.
    Kill,
}

/// Where the stop ladder stands. A kill always carries its drain
/// deadline, so "kill sent" and "draining" cannot disagree.
#[derive(Clone, Copy, Debug)]
enum StopPhase {
    /// Nothing has been asked of the command.
    Running,
    /// A term went out; a kill may still follow.
    TermSent,
    /// A kill went out; output is drained until `drain_until` at most.
    KillSent { drain_until: Instant },
}

impl StopPhase {
    fn kill_sent(self) -> bool {
        matches!(self, Self::KillSent { .. })
    }

    fn after_kill() -> Self {
        Self::KillSent {
            drain_until: Instant::now() + KILL_DRAIN_GRACE,
        }
    }
}

/// How a drain ended: why the command stopped, whether the drain grace
/// ran out with output still pending, and how the stream itself ended.
pub(crate) struct DrainOutcome {
    pub(crate) termination: Termination,
    pub(crate) truncated:   bool,
    pub(crate) stream:      StdResult<(), DockerApiError>,
}

/// Drains `output` into `captured` while racing the caller's term and
/// kill signals, the operation `timeout` measured from `started`, and a
/// sink that stops accepting output. Each of those asks the command to
/// stop through `stop`; a kill starts [`KILL_DRAIN_GRACE`], after which
/// the drain is abandoned and reported truncated. A `stop` that fails
/// ends the drain with its error.
pub(crate) async fn drain_with_stops<F, Fut>(
    captured: &mut StreamOutput,
    output: impl Stream<Item = StdResult<LogOutput, DockerApiError>> + Unpin,
    controls: &ExecControls,
    timeout: Option<Duration>,
    started: Instant,
    mut stop: F,
) -> Result<DrainOutcome>
where
    F: FnMut(StopMode) -> Fut,
    Fut: Future<Output = Result<()>>,
{
    let sink_failed = CancellationToken::new();
    let mut termination = Termination::Exited;
    let mut phase = StopPhase::Running;
    let mut termed = pin!(stop_signal(controls.term.as_ref()));
    let mut killed = pin!(stop_signal(controls.kill.as_ref()));
    let (stream, truncated) = {
        let mut drain = pin!(captured.drain(output, controls.sink.as_ref(), &sink_failed));
        loop {
            let deadline = async {
                match timeout {
                    Some(timeout) if !phase.kill_sent() => {
                        time::sleep(timeout.saturating_sub(started.elapsed())).await;
                    }
                    _ => future::pending().await,
                }
            };
            let drain_timeout = async {
                match phase {
                    StopPhase::KillSent { drain_until } => {
                        time::sleep_until(drain_until.into()).await;
                    }
                    StopPhase::Running | StopPhase::TermSent => future::pending().await,
                }
            };
            tokio::select! {
                outcome = &mut drain => break (outcome, false),
                () = sink_failed.cancelled(), if !phase.kill_sent() => {
                    termination = Termination::Cancelled;
                    phase = StopPhase::after_kill();
                    stop(StopMode::Kill).await?;
                }
                () = &mut termed, if matches!(phase, StopPhase::Running) => {
                    termination = Termination::Cancelled;
                    phase = StopPhase::TermSent;
                    stop(StopMode::Term).await?;
                }
                () = &mut killed, if !phase.kill_sent() => {
                    termination = Termination::Killed;
                    phase = StopPhase::after_kill();
                    stop(StopMode::Kill).await?;
                }
                () = deadline => {
                    termination = Termination::TimedOut;
                    phase = StopPhase::after_kill();
                    stop(StopMode::Kill).await?;
                }
                () = drain_timeout => break (Ok(()), true),
            }
        }
    };
    // A sink that failed as the stream ended never got its kill: send
    // it, so the command does not outlive the caller that stopped
    // listening.
    if sink_failed.is_cancelled() && !phase.kill_sent() {
        termination = Termination::Cancelled;
        stop(StopMode::Kill).await?;
    }
    Ok(DrainOutcome {
        termination,
        truncated,
        stream,
    })
}

/// Captures and sanitizes Docker output while forwarding it to the caller.
/// Its drain future must be polled alongside stop handling: a blocked sink
/// must not prevent a command from being killed.
pub(crate) struct StreamOutput {
    streams: [(OutputStream, OutputSanitizer, OutputCaptureBuffer); 2],
}

impl StreamOutput {
    pub(crate) fn new(policy: OutputSanitization, limit: Option<usize>) -> Self {
        Self {
            streams: [OutputStream::Stdout, OutputStream::Stderr].map(|stream| {
                (
                    stream,
                    OutputSanitizer::new(policy),
                    OutputCaptureBuffer::new(limit),
                )
            }),
        }
    }

    pub(crate) async fn drain(
        &mut self,
        mut output: impl Stream<Item = StdResult<LogOutput, DockerApiError>> + Unpin,
        sink: Option<&OutputSink>,
        sink_failed: &CancellationToken,
    ) -> StdResult<(), DockerApiError> {
        while let Some(chunk) = output.next().await {
            let (index, bytes) = match chunk? {
                LogOutput::StdOut { message } | LogOutput::Console { message } => (0, message),
                LogOutput::StdErr { message } => (1, message),
                LogOutput::StdIn { .. } => continue,
            };
            let (stream, sanitizer, capture) = &mut self.streams[index];
            let bytes = sanitizer.push(&bytes);
            capture.push(&bytes);
            Self::emit(sink, *stream, bytes, sink_failed).await;
        }
        for (stream, sanitizer, capture) in &mut self.streams {
            let bytes = sanitizer.finish();
            capture.push(&bytes);
            Self::emit(sink, *stream, bytes, sink_failed).await;
        }
        Ok(())
    }

    async fn emit(
        sink: Option<&OutputSink>,
        stream: OutputStream,
        bytes: Vec<u8>,
        sink_failed: &CancellationToken,
    ) {
        if !bytes.is_empty() && !sink_failed.is_cancelled() {
            if let Some(sink) = sink {
                if sink(stream, bytes).await.is_err() {
                    sink_failed.cancel();
                }
            }
        }
    }

    pub(crate) fn into_result(
        self,
        termination: Termination,
        exit_code: Option<i32>,
        duration: Duration,
        truncated: bool,
    ) -> ExecStreamingResult {
        let [(_, _, stdout), (_, _, stderr)] = self.streams;
        let (stdout, mut stdout_stats) = stdout.into_parts();
        let (stderr, mut stderr_stats) = stderr.into_parts();
        stdout_stats.truncated = truncated;
        stderr_stats.truncated = truncated;
        let mut result = ExecResult::from_shell_status(termination, exit_code, duration);
        result.stdout = stdout;
        result.stderr = stderr;
        let mut streaming = ExecStreamingResult::new(result);
        streaming.streams_separated = true;
        streaming.live_streaming = true;
        streaming.stdout_capture = stdout_stats;
        streaming.stderr_capture = stderr_stats;
        streaming
    }
}
