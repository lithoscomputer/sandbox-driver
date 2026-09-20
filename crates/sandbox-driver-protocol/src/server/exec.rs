//! `exec/stream`, `exec/stop`, and `one_shot/run`: streaming commands
//! whose output rides a data channel and whose stop tokens are
//! addressable by exec id, plus the frame pumps they share.

use std::collections::hash_map::Entry;
use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use sandbox_driver::{
    Capability, Error, ExecControls, ExecStreamingResult, LogSink, OutputSink, OutputStream,
    Result, StdinSource, StopLevel,
};
use serde_json::Value;
use tokio::io::{AsyncWriteExt, duplex};
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::{Mutex as AsyncMutex, OwnedSemaphorePermit};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tokio_util::task::AbortOnDropHandle;

use super::{DispatchError, ServerState, parse, to_value};
use crate::channel::{Channel, ChannelRequest, FrameKind, FrameReader, FrameWriter};
use crate::methods as m;

pub(super) type SharedWriter = Arc<AsyncMutex<FrameWriter<OwnedWriteHalf>>>;

/// Bytes an exec's sink has written to its data channel, per stream.
#[derive(Default)]
struct Delivered {
    stdout: AtomicU64,
    stderr: AtomicU64,
}

/// A sink that writes every chunk as one frame of its stream, awaiting
/// the connection: a slow host consumer backpressures exactly this
/// operation. `delivered` counts the bytes the channel accepted.
fn frame_sink(writer: &SharedWriter, delivered: &Arc<Delivered>) -> OutputSink {
    let writer = Arc::clone(writer);
    let delivered = Arc::clone(delivered);
    Arc::new(move |stream, chunk| {
        let writer = Arc::clone(&writer);
        let delivered = Arc::clone(&delivered);
        Box::pin(async move {
            let (kind, counter) = match stream {
                OutputStream::Stdout => (FrameKind::Stdout, &delivered.stdout),
                OutputStream::Stderr => (FrameKind::Stderr, &delivered.stderr),
            };
            writer.lock().await.write(kind, &chunk).await?;
            counter.fetch_add(chunk.len() as u64, Ordering::Relaxed);
            Ok(())
        })
    })
}

pub(super) fn log_frame_sink(writer: &SharedWriter) -> LogSink {
    let writer = Arc::clone(writer);
    Arc::new(move |chunk| {
        let writer = Arc::clone(&writer);
        Box::pin(async move { writer.lock().await.write(FrameKind::Stdout, &chunk).await })
    })
}

/// Ends the plugin's side of a channel; a failure here means the host is
/// gone, which the response will report too.
pub(super) async fn finish_channel(writer: &SharedWriter) -> Result<()> {
    writer.lock().await.finish().await
}

/// Pumps the host's `Stdin` frames into `sink` until its `Eof`. The
/// duplex's writer half closing is the command's end-of-file.
fn pump_stdin_frames(
    mut reader: FrameReader<OwnedReadHalf>,
    kill: CancellationToken,
    input_error: Arc<Mutex<Option<Error>>>,
) -> (StdinSource, JoinHandle<()>) {
    let (mut writer, pipe) = duplex(64 * 1024);
    let task = tokio::spawn(async move {
        loop {
            match reader.read().await {
                Ok(Some((FrameKind::Stdin, payload))) => {
                    if writer.write_all(&payload).await.is_err() {
                        // The command stopped reading its input; that is
                        // not an error, and the rest is unwanted.
                        break;
                    }
                }
                Ok(Some((FrameKind::Eof, _)) | None) => break,
                Ok(Some((kind, _))) => {
                    *input_error.lock().expect("input error lock") = Some(Error::invalid_spec(
                        "frame",
                        format!("unexpected {kind:?} on exec input"),
                    ));
                    kill.cancel();
                    break;
                }
                Err(error) => {
                    *input_error.lock().expect("input error lock") = Some(error);
                    kill.cancel();
                    break;
                }
            }
        }
        let _ = writer.shutdown().await;
    });
    (StdinSource::new(pipe), task)
}

/// Reads the host's `Stdin` frames to `Eof` and returns the bytes.
pub(super) async fn collect_stdin_frames(
    reader: &mut FrameReader<OwnedReadHalf>,
    max: usize,
) -> Result<Vec<u8>> {
    let mut content = Vec::new();
    loop {
        match reader.read().await? {
            Some((FrameKind::Stdin, payload)) => {
                if payload.len() > max.saturating_sub(content.len()) {
                    return Err(Error::LimitExceeded {
                        limit:     "buffered_value_bytes".into(),
                        max_bytes: max,
                    });
                }
                content.extend(payload);
            }
            Some((FrameKind::Eof, _)) | None => return Ok(content),
            Some((kind, _)) => {
                return Err(Error::invalid_spec(
                    "frame",
                    format!("unexpected {kind:?} frame on a write channel"),
                ));
            }
        }
    }
}

/// Registration precedes opening the data channel. Its acceptance is the
/// client's proof that a stop can be delivered. Drop also covers channel and
/// stdin failures before provider execution starts.
struct ExecRegistration<'a> {
    state: &'a ServerState,
    id:    &'a str,
    term:  CancellationToken,
    kill:  CancellationToken,
}

impl<'a> ExecRegistration<'a> {
    /// Registers the stop tokens and only then opens the exec's data
    /// channel. Acquiring a channel for a streaming exec *is* registering
    /// it, so the ordering the client relies on cannot be inverted at a
    /// call site, and `Drop` covers a failed channel by construction.
    async fn open(
        state: &'a ServerState,
        id: &'a str,
        request: &ChannelRequest,
        permit: Option<Arc<OwnedSemaphorePermit>>,
    ) -> Result<(Self, Channel)> {
        let term = CancellationToken::new();
        let kill = state.exec_shutdown.child_token();
        {
            let mut execs = state.execs.lock().expect("execs lock");
            match execs.entry(id.to_owned()) {
                Entry::Vacant(entry) => {
                    entry.insert((term.clone(), kill.clone()));
                }
                Entry::Occupied(_) => {
                    return Err(Error::invalid_spec("exec_id", "duplicate execution id"));
                }
            }
        }
        let registration = Self {
            state,
            id,
            term,
            kill,
        };
        let channel = state.open_channel(request, permit).await?;
        Ok((registration, channel))
    }
}

impl Drop for ExecRegistration<'_> {
    fn drop(&mut self) {
        self.state.execs.lock().expect("execs lock").remove(self.id);
    }
}

/// Runs a streaming command whose output goes to the channel and whose
/// stop tokens are addressable by `exec_id`, then closes the channel
/// before the result is returned.
async fn stream_through_channel<F, Fut>(
    registration: ExecRegistration<'_>,
    channel: Channel,
    stdin: bool,
    run: F,
) -> Result<ExecStreamingResult>
where
    F: FnOnce(ExecControls) -> Fut,
    Fut: Future<Output = Result<ExecStreamingResult>>,
{
    let Channel { reader, writer } = channel;
    let writer: SharedWriter = Arc::new(AsyncMutex::new(writer));
    let input_error = Arc::new(Mutex::new(None));
    let (stdin_source, stdin_task) = if stdin {
        let (source, task) =
            pump_stdin_frames(reader, registration.kill.clone(), Arc::clone(&input_error));
        (Some(source), Some(AbortOnDropHandle::new(task)))
    } else {
        (None, None)
    };
    let delivered = Arc::new(Delivered::default());
    let controls = ExecControls {
        term:                  Some(registration.term.clone()),
        kill:                  Some(registration.kill.clone()),
        stdin:                 stdin_source,
        sink:                  Some(frame_sink(&writer, &delivered)),
        // The host captures the frames. Retaining another copy here
        // would grow memory with output the response never contains.
        retained_output_limit: Some(0),
    };
    let outcome = run(controls).await;
    if let Some(task) = stdin_task {
        task.abort();
    }
    finish_channel(&writer).await?;
    tracing::debug!(
        exec_id = registration.id,
        stdout_bytes = delivered.stdout.load(Ordering::Relaxed),
        stderr_bytes = delivered.stderr.load(Ordering::Relaxed),
        truncated = outcome
            .as_ref()
            .is_ok_and(|streaming| streaming.stdout_capture.truncated
                || streaming.stderr_capture.truncated),
        "exec output delivered to its data channel before the response"
    );
    if let Some(error) = input_error.lock().expect("input error lock").take() {
        return Err(error);
    }
    outcome
}

fn stream_result(streaming: &ExecStreamingResult) -> m::ExecStreamResult {
    m::ExecStreamResult {
        result:            m::ExecResultDto::from_result(&streaming.result),
        streams_separated: streaming.streams_separated,
        live_streaming:    streaming.live_streaming,
        stdout_capture:    streaming.stdout_capture,
        stderr_capture:    streaming.stderr_capture,
        output_loss:       streaming.output_loss,
    }
}

pub(super) async fn dispatch(
    state: &Arc<ServerState>,
    method: &str,
    params: Value,
    io_permit: Option<Arc<OwnedSemaphorePermit>>,
) -> Result<Value, DispatchError> {
    match method {
        m::EXEC_STREAM => {
            let request: m::ExecStreamParams = parse(params)?;
            let handle = state.sandbox(&request.sandbox_id).await?;
            let mut spec = request.spec.into_spec();
            let (registration, mut channel) =
                ExecRegistration::open(state, &request.exec_id, &request.channel, io_permit)
                    .await?;
            // A provider without streamed stdin takes the input as the
            // spec's fixed bytes, so the host's stream still reaches the
            // command; one without any stdin then rejects it honestly.
            let stream_stdin = request.stdin && handle.capabilities().exec.stdin_stream;
            if request.stdin && !stream_stdin {
                spec.stdin = Some(
                    collect_stdin_frames(&mut channel.reader, state.limits.buffered_value_bytes)
                        .await?,
                );
            }
            let streaming = stream_through_channel(
                registration,
                channel,
                stream_stdin,
                |controls| async move { handle.exec().run_streaming(&spec, controls).await },
            )
            .await?;
            to_value(&stream_result(&streaming))
        }
        m::ONE_SHOT_RUN => {
            let request: m::OneShotRunParams = parse(params)?;
            let handle = state.sandbox(&request.sandbox_id).await?;
            let one_shot = handle
                .one_shot()
                .ok_or_else(|| Error::unsupported(Capability::OneShot))?;
            let (registration, channel) =
                ExecRegistration::open(state, &request.exec_id, &request.channel, io_permit)
                    .await?;
            let spec = request.spec;
            let streaming =
                stream_through_channel(registration, channel, false, |controls| async move {
                    one_shot.run(&spec, controls).await
                })
                .await?;
            to_value(&stream_result(&streaming))
        }
        m::EXEC_STOP => {
            let request: m::ExecStopParams = parse(params)?;
            let tokens = state
                .execs
                .lock()
                .expect("execs lock")
                .get(&request.exec_id)
                .cloned();
            if let Some((term, kill)) = tokens {
                match request.level {
                    StopLevel::Term => term.cancel(),
                    StopLevel::Kill => kill.cancel(),
                }
            }
            to_value(&m::Empty)
        }
        _ => Err(DispatchError::UnknownMethod),
    }
}
