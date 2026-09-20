//! Output of a Docker exec or one-shot container: captured and sanitized
//! while it streams to the caller, and drained under the stop race every
//! Docker command shares with the other providers.

use std::pin::pin;
use std::result::Result as StdResult;
use std::time::Duration;

use bollard::container::LogOutput;
use bollard::errors::Error as DockerApiError;
use futures_util::{Stream, StreamExt};
use sandbox_driver::{
    ExecControls, ExecResult, ExecStreamingResult, OutputCaptureBuffer, OutputSanitization,
    OutputSanitizer, OutputSink, OutputStream, Result, StopLevel, Termination,
};
use tokio_util::sync::CancellationToken;

/// Grace period for draining output after a kill request. Must exceed
/// the exec watcher's poll interval.
pub(crate) const KILL_DRAIN_GRACE: Duration = Duration::from_secs(10);

/// How a drain ended: why the command stopped, whether the drain grace
/// ran out with output still pending, and how the stream itself ended.
pub(crate) struct DrainOutcome {
    pub(crate) termination: Termination,
    pub(crate) truncated:   bool,
    pub(crate) stream:      StdResult<(), DockerApiError>,
}

/// Drains `output` into `captured` under [`sandbox_driver::drain_with_stops`]
/// with the operation `timeout` that remains and [`KILL_DRAIN_GRACE`]; a
/// drain the grace abandoned is reported truncated with its stream intact.
pub(crate) async fn drain_with_stops<F, Fut>(
    captured: &mut StreamOutput,
    output: impl Stream<Item = StdResult<LogOutput, DockerApiError>> + Unpin,
    controls: &ExecControls,
    timeout: Option<Duration>,
    stop: F,
) -> Result<DrainOutcome>
where
    F: FnMut(StopLevel) -> Fut,
    Fut: Future<Output = Result<()>>,
{
    let sink_failed = CancellationToken::new();
    let mut drain = pin!(captured.drain(output, controls.sink.as_ref(), &sink_failed));
    let outcome = sandbox_driver::drain_with_stops(
        drain.as_mut(),
        &sink_failed,
        controls,
        timeout,
        KILL_DRAIN_GRACE,
        stop,
    )
    .await?;
    let (stream, truncated) = match outcome.drained {
        Some(stream) => (stream, false),
        None => (Ok(()), true),
    };
    Ok(DrainOutcome {
        termination: outcome.termination,
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
