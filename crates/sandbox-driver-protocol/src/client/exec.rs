//! Streaming exec, one-shot runs, and stdio processes: the operations
//! whose bytes ride an exec-style data channel.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use sandbox_driver::{
    Error, Exec, ExecControls, ExecResult, ExecSpec, ExecStreamingResult, IncompleteOperation,
    OneShot, OneShotSpec, OutputCaptureBuffer, OutputStream, Result, SandboxId, SpawnSpec,
    StderrTail, StdinReader, StdioProcess, StdioProcessHandle, Termination, TransportError,
};
use serde::Serialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};
use tokio::net::unix::OwnedWriteHalf;
use tokio::sync::{Mutex as AsyncMutex, OnceCell, OwnedSemaphorePermit};
use tokio::time;
use tokio_util::sync::CancellationToken;
use tokio_util::task::AbortOnDropHandle;

use super::Client;
use crate::channel::{self, Channel, ChannelReceiver, FrameKind, FrameWriter, WriteStall};
use crate::methods as m;

/// What an exec pump collected while the command ran.
struct PumpedOutput {
    stdout:     OutputCaptureBuffer,
    stderr:     OutputCaptureBuffer,
    /// The caller's sink failed on this chunk: the command was killed and
    /// the result reports a cancellation.
    sink_error: Option<Error>,
}

/// What the plugin has confirmed about an exec, read when a hard cancel
/// abandons the operation before its result arrives.
#[derive(Default)]
pub(super) struct ExecProgress {
    /// The plugin answered the kill request.
    pub(super) stop_acknowledged:     AtomicBool,
    /// The plugin's result said the command exited or was killed.
    pub(super) termination_confirmed: AtomicBool,
}

impl ExecProgress {
    fn incomplete(&self, operation: &'static str) -> IncompleteOperation {
        let mut outcome = IncompleteOperation::new(operation);
        outcome.stop_acknowledged = self.stop_acknowledged.load(Ordering::SeqCst);
        outcome.termination_confirmed = self.termination_confirmed.load(Ordering::SeqCst);
        outcome
    }
}

/// Pumps one exec's channel: output frames go to the capture buffers and
/// the caller's sink, stdin bytes go out as frames. Ends when the plugin
/// sends its `Eof`.
async fn pump_exec_channel(
    client: &Arc<Client>,
    exec_id: &str,
    channel: Channel,
    stdin: Option<StdinReader>,
    controls: &ExecControls,
    progress: &Arc<ExecProgress>,
) -> Result<PumpedOutput> {
    let Channel { mut reader, writer } = channel;
    // The server registers stop tokens before opening this channel. Waiting
    // for acceptance prevents an already-cancelled token overtaking exec.
    let _stop_task = client
        .forward_stops(exec_id, controls, Arc::clone(progress))
        .map(AbortOnDropHandle::new);
    let input_error = Arc::new(Mutex::new(None));
    let _stdin_task = stdin.map(|reader| {
        let input_error = Arc::clone(&input_error);
        let kill = controls.kill.clone();
        AbortOnDropHandle::new(tokio::spawn(async move {
            if let Err(error) = feed_stdin_frames(reader, writer).await {
                *input_error.lock().expect("input error lock") = Some(error);
                if let Some(kill) = kill {
                    kill.cancel();
                }
            }
        }))
    });
    let mut output = PumpedOutput {
        stdout:     OutputCaptureBuffer::new(controls.retained_output_limit),
        stderr:     OutputCaptureBuffer::new(controls.retained_output_limit),
        sink_error: None,
    };
    loop {
        let Some(frame) = reader.read().await? else {
            break;
        };
        let (stream, payload) = match frame {
            (FrameKind::Stdout, payload) => (OutputStream::Stdout, payload),
            (FrameKind::Stderr, payload) => (OutputStream::Stderr, payload),
            (FrameKind::Eof, _) => break,
            (kind, _) => {
                return Err(Error::invalid_spec(
                    "frame",
                    format!("unexpected {kind:?} frame on exec output"),
                ));
            }
        };
        match stream {
            OutputStream::Stdout => output.stdout.push(&payload),
            OutputStream::Stderr => output.stderr.push(&payload),
        }
        if output.sink_error.is_some() || payload.is_empty() {
            continue;
        }
        if let Some(sink) = &controls.sink {
            let delivered =
                time::timeout(client.limits.output_progress_timeout, sink(stream, payload))
                    .await
                    .unwrap_or_else(|_| {
                        Err(Error::Transport(TransportError::new(
                            "output sink made no progress",
                        )))
                    });
            if let Err(error) = delivered {
                // A failing sink is a hard stop on every provider; the
                // rest of the stream is drained and dropped.
                if let Some(kill) = &controls.kill {
                    kill.cancel();
                }
                output.sink_error = Some(error);
            }
        }
    }
    if let Some(error) = input_error.lock().expect("input error lock").take() {
        return Err(error);
    }
    Ok(output)
}

/// Copies `reader` into the channel as `Stdin` frames, then sends the
/// host's `Eof`. A channel the plugin closed is the command declining
/// its input, which is not an error.
async fn feed_stdin_frames(
    mut reader: StdinReader,
    mut writer: FrameWriter<OwnedWriteHalf>,
) -> Result<()> {
    let mut buffer = vec![0; 32 * 1024];
    loop {
        let read = reader
            .read(&mut buffer)
            .await
            .map_err(|error| Error::io("reading exec stdin source", error))?;
        if read == 0 {
            break;
        }
        // A process may close stdin without consuming all input. A source
        // read error, unlike that normal refusal, must fail the operation.
        if writer
            .write(FrameKind::Stdin, &buffer[..read])
            .await
            .is_err()
        {
            return Ok(());
        }
    }
    let _ = writer.finish().await;
    Ok(())
}

/// Runs a channel-backed command to its result: sends the request, pumps
/// the channel, forwards stops, and assembles the result from the host's
/// retained copy plus the plugin's metadata.
pub(super) async fn run_channel_exec<P: Serialize>(
    client: &Arc<Client>,
    method: &str,
    params: &P,
    exec_id: &str,
    receiver: ChannelReceiver,
    stdin: Option<StdinReader>,
    controls: &ExecControls,
) -> Result<ExecStreamingResult> {
    if controls
        .retained_output_limit
        .is_some_and(|limit| limit > client.limits.retained_output_bytes)
    {
        return Err(Error::LimitExceeded {
            limit:     "retained_output_bytes".into(),
            max_bytes: client.limits.retained_output_bytes,
        });
    }
    let mut controls = controls.clone();
    let kill = controls
        .kill
        .get_or_insert_with(CancellationToken::new)
        .clone();
    let drain_deadline = async {
        kill.cancelled().await;
        time::sleep(client.limits.hard_cancel_drain_timeout).await;
    };
    let progress = Arc::new(ExecProgress::default());
    let execution = client.call_with_channel(
        method,
        async {
            let result = client
                .call::<_, m::ExecStreamResult>(method, params)
                .await?;
            progress.termination_confirmed.store(
                matches!(
                    result.result.termination,
                    Termination::Exited | Termination::Killed
                ),
                Ordering::SeqCst,
            );
            Ok(result)
        },
        receiver,
        |channel| pump_exec_channel(client, exec_id, channel, stdin, &controls, &progress),
    );
    let (result, pumped) = tokio::select! {
        result = execution => result?,
        () = drain_deadline => {
            return Err(Error::Incomplete(progress.incomplete("hard cancellation drain")));
        },
    };
    let (stdout, mut stdout_stats) = pumped.stdout.into_parts();
    let (stderr, mut stderr_stats) = pumped.stderr.into_parts();
    stdout_stats.truncated = result.stdout_capture.truncated || pumped.sink_error.is_some();
    stderr_stats.truncated = result.stderr_capture.truncated || pumped.sink_error.is_some();
    let mut exec_result = result.result.into_result(stdout, stderr);
    if pumped.sink_error.is_some() {
        exec_result.termination = Termination::Cancelled;
    }
    let mut streaming = ExecStreamingResult::new(exec_result);
    streaming.streams_separated = result.streams_separated;
    streaming.live_streaming = result.live_streaming;
    streaming.stdout_capture = stdout_stats;
    streaming.stderr_capture = stderr_stats;
    streaming.output_loss = result.output_loss;
    Ok(streaming)
}

pub(super) struct SandboxExec {
    pub(super) client:     Arc<Client>,
    pub(super) sandbox_id: SandboxId,
}

#[async_trait]
impl Exec for SandboxExec {
    async fn run(&self, spec: &ExecSpec) -> Result<ExecResult> {
        let streaming = self
            .run_streaming(spec, ExecControls {
                retained_output_limit: Some(self.client.limits.retained_output_bytes),
                ..ExecControls::default()
            })
            .await?;
        streaming.into_complete()
    }

    async fn run_streaming(
        &self,
        spec: &ExecSpec,
        controls: ExecControls,
    ) -> Result<ExecStreamingResult> {
        let exec_id = self.client.next_exec_id(&self.sandbox_id);
        let stdin = controls.stdin_reader(spec);
        let (channel, receiver) = self.client.listener.expect()?;
        let params = m::ExecStreamParams {
            sandbox_id: self.sandbox_id.as_str().to_owned(),
            exec_id: exec_id.clone(),
            channel,
            spec: m::ExecSpecDto::from_spec(spec),
            stdin: stdin.is_some(),
            retained_output_limit: controls.retained_output_limit,
        };
        run_channel_exec(
            &self.client,
            m::EXEC_STREAM,
            &params,
            &exec_id,
            receiver,
            stdin,
            &controls,
        )
        .await
    }

    async fn spawn_stdio(&self, spec: &SpawnSpec) -> Result<StdioProcess> {
        let process_id = self.client.next_stream_id("stdio");
        let (channel, receiver) = self.client.listener.expect()?;
        let permit = receiver.io_permit();
        let _: m::Empty = self
            .client
            .call(m::EXEC_STDIO_OPEN, &m::StdioOpenParams {
                sandbox_id: self.sandbox_id.as_str().to_owned(),
                process_id: process_id.clone(),
                channel,
                spec: spec.clone(),
            })
            .await?;
        let Channel { mut reader, writer } = receiver.accept_soon().await?;

        let (stdin_writer, stdin_reader) = duplex(64 * 1024);
        let input_task = tokio::spawn(feed_stdin_frames(Box::pin(stdin_reader), writer));

        let (mut stdout_writer, stdout_reader) = duplex(64 * 1024);
        let stderr_tail = StderrTail::default();
        let output_tail = stderr_tail.clone();
        let stopped = CancellationToken::new();
        let output_stopped = stopped.clone();
        let output_id = process_id.clone();
        let output_client = Arc::clone(&self.client);
        let output_task = tokio::spawn(async move {
            let outcome = async {
                loop {
                    match reader.read().await? {
                        Some((FrameKind::Stdout, payload)) => {
                            channel::write_with_progress(
                                &mut stdout_writer,
                                &payload,
                                output_client.limits.output_progress_timeout,
                            )
                            .await
                            .map_err(|stall| match stall {
                                WriteStall::Timeout => Error::Incomplete(IncompleteOperation::new(
                                    "stdio output progress",
                                )),
                                WriteStall::Io(error) => Error::io("writing stdio output", error),
                            })?;
                        }
                        Some((FrameKind::Stderr, payload)) => output_tail.push(&payload),
                        Some((FrameKind::Eof, _)) | None => return Ok(()),
                        Some((kind, _)) => {
                            return Err(Error::invalid_spec(
                                "frame",
                                format!("unexpected {kind:?} on stdio output"),
                            ));
                        }
                    }
                }
            }
            .await;
            if outcome.is_err() {
                output_stopped.cancel();
                let _ = time::timeout(
                    output_client.limits.hard_cancel_drain_timeout,
                    output_client.cleanup_call(m::EXEC_STDIO_TERMINATE, &m::StdioIdParams {
                        process_id: output_id,
                    }),
                )
                .await;
            }
            let _ = stdout_writer.shutdown().await;
            outcome
        });

        let handle = RemoteStdioHandle {
            client: Arc::clone(&self.client),
            permit: Mutex::new(Some(permit)),
            stopped,
            process_id,
            stderr_tail: stderr_tail.clone(),
            outcome: OnceCell::new(),
            input_task: AsyncMutex::new(Some(AbortOnDropHandle::new(input_task))),
            output_task: AsyncMutex::new(Some(AbortOnDropHandle::new(output_task))),
        };
        Ok(StdioProcess {
            stdin: Box::pin(stdin_writer),
            stdout: Box::pin(stdout_reader),
            stderr_tail,
            handle: Box::new(handle),
        })
    }
}

pub(super) struct SandboxOneShot {
    pub(super) client:     Arc<Client>,
    pub(super) sandbox_id: SandboxId,
}

#[async_trait]
impl OneShot for SandboxOneShot {
    async fn run(&self, spec: &OneShotSpec, controls: ExecControls) -> Result<ExecStreamingResult> {
        let exec_id = self.client.next_exec_id(&self.sandbox_id);
        let (channel, receiver) = self.client.listener.expect()?;
        let params = m::OneShotRunParams {
            sandbox_id: self.sandbox_id.as_str().to_owned(),
            exec_id: exec_id.clone(),
            channel,
            spec: spec.clone(),
            retained_output_limit: controls.retained_output_limit,
        };
        run_channel_exec(
            &self.client,
            m::ONE_SHOT_RUN,
            &params,
            &exec_id,
            receiver,
            None,
            &controls,
        )
        .await
    }
}

struct RemoteStdioHandle {
    permit:      Mutex<Option<Arc<OwnedSemaphorePermit>>>,
    stopped:     CancellationToken,
    client:      Arc<Client>,
    process_id:  String,
    stderr_tail: StderrTail,
    outcome:     OnceCell<(Termination, Option<i32>)>,
    input_task:  AsyncMutex<Option<AbortOnDropHandle<Result<()>>>>,
    output_task: AsyncMutex<Option<AbortOnDropHandle<Result<()>>>>,
}

impl Drop for RemoteStdioHandle {
    fn drop(&mut self) {
        let Some(permit) = self.permit.get_mut().expect("stdio permit lock").take() else {
            return;
        };
        let client = Arc::clone(&self.client);
        let process_id = self.process_id.clone();
        self.client.own_cleanup(permit, async move {
            let params = m::StdioIdParams { process_id };
            client
                .cleanup_call(m::EXEC_STDIO_TERMINATE, &params)
                .await?;
            loop {
                match client
                    .call::<_, m::StdioWaitResult>(m::EXEC_STDIO_WAIT, &params)
                    .await
                {
                    Err(Error::Overloaded { .. }) => time::sleep(Duration::from_millis(1)).await,
                    outcome => return outcome.map(|_| ()),
                }
            }
        });
    }
}

#[async_trait]
impl StdioProcessHandle for RemoteStdioHandle {
    #[tracing::instrument(skip_all, fields(process_id = %self.process_id))]
    async fn terminate(&self) {
        self.stopped.cancel();
        let outcome = time::timeout(
            self.client.limits.hard_cancel_drain_timeout,
            self.client
                .cleanup_call(m::EXEC_STDIO_TERMINATE, &m::StdioIdParams {
                    process_id: self.process_id.clone(),
                }),
        )
        .await;
        if !matches!(outcome, Ok(Ok(()))) {
            tracing::warn!("plugin stdio termination is unconfirmed");
        }
    }

    #[tracing::instrument(skip_all, fields(process_id = %self.process_id))]
    async fn wait(&self) -> (Termination, Option<i32>) {
        *self
            .outcome
            .get_or_init(|| async {
                let params = m::StdioIdParams { process_id: self.process_id.clone() };
                let result: Result<m::StdioWaitResult> = tokio::select! {
                    result = self.client.call(m::EXEC_STDIO_WAIT, &params) => result,
                    () = async { self.stopped.cancelled().await; time::sleep(self.client.limits.hard_cancel_drain_timeout).await; } => {
                        self.output_task.lock().await.take();
                        self.input_task.lock().await.take();
                        return (Termination::Unknown, None);
                    }
                };
                let result = match result {
                    Ok(result) => result,
                    Err(error) => {
                        tracing::error!(error = %error, "plugin stdio wait failed");
                        return (Termination::Unknown, None);
                    }
                };
                // The provider wait completed. Cleanup no longer needs to
                // retain separate admission, even if local output later fails.
                self.permit.lock().expect("stdio permit lock").take();
                if let Some(task) = self.output_task.lock().await.take() {
                    if !matches!(time::timeout(self.client.limits.hard_cancel_drain_timeout, task).await, Ok(Ok(Ok(())))) {
                        self.input_task.lock().await.take();
                        return (Termination::Unknown, None);
                    }
                }
                if !result.stderr_tail.is_empty() {
                    self.stderr_tail.push(result.stderr_tail.as_bytes());
                }
                if let Some(task) = self.input_task.lock().await.take() {
                    task.abort();
                }
                (result.termination, result.exit_code)
            })
            .await
    }
}
