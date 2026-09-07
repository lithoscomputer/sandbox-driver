//! Serves any [`SandboxProvider`] over newline-delimited JSON-RPC.
//!
//! Every request is handled in its own task, so a slow call never blocks
//! its siblings (the interleaving requirement from the design). One
//! writer task owns the control stream; events cross as notifications and
//! every byte stream rides a data channel the plugin opens back to the
//! host ([`crate::channel`]).

use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::future::Future;
use std::io;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use async_trait::async_trait;
use sandbox_driver::{
    Capability, Error, Event, EventContext, EventObserver, ExecControls, ExecStreamingResult,
    Filesystem, LogSink, OutputSink, OutputStream, Result, Sandbox, SandboxId, SandboxProvider,
    SandboxSpec, SandboxStatus, SnapshotId, StderrTail, StdinSource, StdioProcessHandle, StopLevel,
    TransportError, VolumeId,
};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;
use tokio::io::{
    AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, duplex, stdin, stdout,
};
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::runtime::Handle as RuntimeHandle;
use tokio::sync::{Mutex as AsyncMutex, OwnedSemaphorePermit, Semaphore};
use tokio::task::{JoinHandle, JoinSet};
use tokio::time;
use tokio_util::sync::CancellationToken;
use tokio_util::task::AbortOnDropHandle;

use crate::channel::{
    self, Channel, ChannelRequest, DataTransport, FrameKind, FrameReader, FrameWriter,
};
use crate::wire::{CODE_INVALID_REQUEST, CODE_METHOD_NOT_FOUND, Message, WireError};
use crate::{ServerDiagnostics, TransportLimits, control, limits, methods as m};

/// Serves `provider` over this process's stdin and stdout until EOF or
/// `shutdown` — the main loop of a plugin binary:
///
/// ```ignore
/// #[tokio::main]
/// async fn main() -> sandbox_driver::Result<()> {
///     serve_stdio(Arc::new(MyProvider::new())).await
/// }
/// ```
///
/// Stdout belongs to the protocol; a plugin must log to stderr only.
pub async fn serve_stdio(provider: Arc<dyn SandboxProvider>) -> Result<()> {
    serve(provider, stdin(), stdout()).await
}

/// Serves `provider` over the byte streams until EOF or `shutdown`.
///
/// This is the plugin-side main loop: a provider binary calls it with
/// stdin/stdout. It also runs over any in-process duplex, which is how
/// the conformance tests drive it; the data channels are real Unix
/// sockets either way.
#[tracing::instrument(skip_all, fields(provider_kind = %provider.kind()), err)]
pub async fn serve(
    provider: Arc<dyn SandboxProvider>,
    reader: impl AsyncRead + Unpin + Send + 'static,
    writer: impl AsyncWrite + Unpin + Send + 'static,
) -> Result<()> {
    serve_with_limits(provider, reader, writer, TransportLimits::default()).await
}

/// Serves a plugin with finite local admission and delivery budgets.
pub async fn serve_with_limits(
    provider: Arc<dyn SandboxProvider>,
    reader: impl AsyncRead + Unpin + Send + 'static,
    writer: impl AsyncWrite + Unpin + Send + 'static,
    limits: TransportLimits,
) -> Result<()> {
    limits.validate()?;
    let (outbound, mut outbound_rx) = control::queue(&limits);
    let progress_timeout = limits.output_progress_timeout;
    let mut writer_task = AbortOnDropHandle::new(tokio::spawn(async move {
        let mut writer = writer;
        while let Some(message) = outbound_rx.recv().await {
            time::timeout(progress_timeout, async {
                writer.write_all(&message.bytes).await?;
                writer.flush().await
            })
            .await
            .map_err(|_| {
                Error::Transport(TransportError::new("control response delivery timed out"))
            })?
            .map_err(|error| {
                Error::Transport(TransportError::with_source(
                    "writing plugin response",
                    error,
                ))
            })?;
        }
        writer
            .shutdown()
            .await
            .map_err(|error| Error::io("closing plugin response transport", error))
    }));
    let request_budget = Arc::new(Semaphore::new(limits.provider_requests));
    let reserved_budget = Arc::new(Semaphore::new(limits.reserved_requests));
    let io_budget = Arc::new(Semaphore::new(limits.active_io));
    let mut requests = JoinSet::new();
    let state = Arc::new(ServerState {
        provider,
        transport: OnceLock::new(),
        open_budget: Arc::new(Semaphore::new(limits.pending_opens)),
        io_budget: Arc::clone(&io_budget),
        handles: Mutex::new(HashMap::new()),
        execs: Mutex::new(HashMap::new()),
        exec_shutdown: CancellationToken::new(),
        stdios: Mutex::new(HashMap::new()),
        ptys: Mutex::new(HashMap::new()),
        streams: Mutex::new(HashMap::new()),
        outbound: outbound.clone(),
        limits: limits.clone(),
        delivery_failed: CancellationToken::new(),
        events_failed: Arc::new(AtomicBool::new(false)),
        background: Mutex::new(Vec::new()),
    });

    let mut reader = BufReader::new(reader);
    let mut partial = Vec::new();
    let mut writer_finished = false;
    let outcome = loop {
        let line = tokio::select! {
            biased;
            () = state.delivery_failed.cancelled() => break Err(Error::Transport(TransportError::new("control delivery failed; provider effects may be uncertain"))),
            result = requests.join_next(), if !requests.is_empty() => {
                if result.is_some_and(|result| result.is_err()) {
                    break Err(Error::Transport(TransportError::new("plugin request task failed")));
                }
                continue;
            }
            line = control::read_line(&mut reader, &mut partial, limits.control_message_bytes) => line,
            writer_result = &mut writer_task => {
                writer_finished = true;
                break match writer_result {
                    Ok(result) => result,
                    Err(error) => Err(Error::Transport(TransportError::with_source(
                        "joining plugin response writer",
                        error,
                    ))),
                };
            }
        };
        let line = match line {
            Ok(Some(line)) => line,
            Ok(None) => break Ok(()),
            Err(error) => {
                break Err(Error::Transport(TransportError::with_source(
                    "reading plugin request",
                    error,
                )));
            }
        };
        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        let message: Message = match serde_json::from_slice(&line) {
            Ok(message) => message,
            Err(error) => {
                if outbound
                    .send(
                        &Message::error_response(0, WireError {
                            code:    CODE_INVALID_REQUEST,
                            message: format!(
                                "malformed message at line {} column {}",
                                error.line(),
                                error.column()
                            ),
                            data:    None,
                        }),
                        true,
                    )
                    .is_err()
                {
                    state.delivery_failed.cancel();
                }
                continue;
            }
        };
        let (Some(id), Some(method)) = (message.id, message.method.clone()) else {
            // There are no host→plugin notifications; ignore.
            continue;
        };
        if method == m::SHUTDOWN {
            if let Err(error) = outbound
                .deliver(
                    &Message::response(id, Value::Null),
                    true,
                    limits.output_progress_timeout,
                )
                .await
            {
                break Err(Error::Transport(TransportError::with_source(
                    "sending plugin shutdown response",
                    error,
                )));
            }
            // Do not poll stdin again: Tokio stdin can start a blocking read
            // that cancellation cannot stop, keeping the process alive.
            break Ok(());
        }
        let priority = limits::reserved(&method);
        let admission = (|| {
            let request = limits::acquire(
                if priority {
                    &reserved_budget
                } else {
                    &request_budget
                },
                if priority {
                    "reserved_requests"
                } else {
                    "provider_requests"
                },
            )?;
            let io = if limits::uses_io(&method) {
                Some(Arc::new(limits::acquire(&io_budget, "active_io")?))
            } else {
                None
            };
            Ok::<_, Error>((request, io))
        })();
        let (request_permit, io_permit) = match admission {
            Ok(permits) => permits,
            Err(error) => {
                if outbound
                    .deliver(
                        &Message::error_response(id, WireError::from_error(&error)),
                        true,
                        limits.output_progress_timeout,
                    )
                    .await
                    .is_err()
                {
                    state.delivery_failed.cancel();
                }
                continue;
            }
        };
        let stream_id = if matches!(method.as_str(), m::LOGS_FOLLOW | m::SNAPSHOT_BUILD_LOGS) {
            message
                .params
                .as_ref()
                .and_then(|params| params.get("stream_id"))
                .and_then(Value::as_str)
                .map(str::to_owned)
        } else {
            None
        };
        if let Some(stream) = &stream_id {
            let mut streams = state.streams.lock().expect("streams lock");
            if streams.contains_key(stream) {
                if outbound
                    .send(
                        &Message::error_response(
                            id,
                            WireError::from_error(&Error::invalid_spec(
                                "stream_id",
                                "duplicate stream id",
                            )),
                        ),
                        true,
                    )
                    .is_err()
                {
                    state.delivery_failed.cancel();
                }
                continue;
            }
            streams.insert(stream.clone(), state.exec_shutdown.child_token());
        }
        let state = Arc::clone(&state);
        requests.spawn(async move {
            let _request_permit = request_permit;
            let params = message.params.unwrap_or(Value::Null);
            let reply = match dispatch(&state, &method, params, io_permit).await {
                Ok(result) => Message::response(id, result),
                Err(DispatchError::UnknownMethod) => Message::error_response(id, WireError {
                    code:    CODE_METHOD_NOT_FOUND,
                    message: format!("unknown method {method}"),
                    data:    None,
                }),
                Err(DispatchError::BadParams(error)) => Message::error_response(id, WireError {
                    code:    CODE_INVALID_REQUEST,
                    message: format!(
                        "invalid params for {method} at line {} column {}",
                        error.line(),
                        error.column()
                    ),
                    data:    None,
                }),
                Err(DispatchError::App(error)) => {
                    Message::error_response(id, WireError::from_error(&error))
                }
            };
            if let Some(stream) = stream_id {
                state.streams.lock().expect("streams lock").remove(&stream);
            }
            let delivery = state
                .outbound
                .deliver(&reply, priority, state.limits.output_progress_timeout)
                .await;
            let delivery = match delivery {
                Err(error @ Error::LimitExceeded { .. }) => {
                    let reply = Message::error_response(id, WireError::from_error(&error));
                    state
                        .outbound
                        .deliver(&reply, true, state.limits.output_progress_timeout)
                        .await
                }
                outcome => outcome,
            };
            if delivery.is_err() {
                state.delivery_failed.cancel();
            }
        });
    };

    let cleanup = time::timeout(limits.shutdown_timeout, async {
        state.close_sessions().await;
        while requests.join_next().await.is_some() {}
    })
    .await;
    requests.abort_all();
    while requests.join_next().await.is_some() {}
    state
        .background
        .lock()
        .expect("background tasks lock")
        .clear();
    drop(outbound);
    drop(state);
    let writer_outcome = if writer_finished {
        Ok(())
    } else {
        time::timeout(limits.shutdown_timeout, &mut writer_task)
            .await
            .map_err(|_| {
                Error::Transport(TransportError::new("plugin response shutdown timed out"))
            })?
            .map_err(|error| {
                Error::Transport(TransportError::with_source(
                    "joining plugin response writer",
                    error,
                ))
            })?
    };
    outcome?;
    cleanup.map_err(|_| {
        Error::Transport(TransportError::new(
            "plugin cleanup incomplete at shutdown deadline",
        ))
    })?;
    writer_outcome
}

struct ServerState {
    provider:        Arc<dyn SandboxProvider>,
    /// Set by `initialize`; every data channel opens against it.
    transport:       OnceLock<DataTransport>,
    open_budget:     Arc<Semaphore>,
    io_budget:       Arc<Semaphore>,
    handles:         Mutex<HashMap<String, Arc<dyn Sandbox>>>,
    /// Per in-flight exec: its `term` and `kill` tokens, in that order.
    execs:           Mutex<HashMap<String, (CancellationToken, CancellationToken)>>,
    exec_shutdown:   CancellationToken,
    stdios:          Mutex<HashMap<String, Arc<ServerStdio>>>,
    ptys:            Mutex<HashMap<String, Arc<ServerPty>>>,
    streams:         Mutex<HashMap<String, CancellationToken>>,
    outbound:        control::ControlSender,
    limits:          TransportLimits,
    delivery_failed: CancellationToken,
    events_failed:   Arc<AtomicBool>,
    background:      Mutex<Vec<AbortOnDropHandle<()>>>,
}

impl ServerState {
    fn own(&self, future: impl Future<Output = ()> + Send + 'static) {
        let mut tasks = self.background.lock().expect("background tasks lock");
        tasks.retain(|task| !task.is_finished());
        tasks.push(AbortOnDropHandle::new(tokio::spawn(future)));
    }

    async fn close_sessions(&self) {
        // A closing connection has no caller left to escalate, so every
        // in-flight exec is killed outright.
        // Child tokens also cancel requests that have not yet registered.
        self.exec_shutdown.cancel();
        self.execs.lock().expect("execs lock").clear();
        let streams = self
            .streams
            .lock()
            .expect("streams lock")
            .drain()
            .map(|(_, token)| token)
            .collect::<Vec<_>>();
        for token in streams {
            token.cancel();
        }

        let stdios = self
            .stdios
            .lock()
            .expect("stdios lock")
            .drain()
            .map(|(_, handle)| handle)
            .collect::<Vec<_>>();
        for process in stdios {
            process.handle.terminate().await;
        }

        let ptys = self
            .ptys
            .lock()
            .expect("ptys lock")
            .drain()
            .map(|(_, session)| session)
            .collect::<Vec<_>>();
        for session in ptys {
            if let Err(error) = session.session.close().await {
                tracing::warn!(error = %error, "plugin PTY cleanup failed");
            }
        }
    }

    async fn sandbox(&self, id: &str) -> Result<Arc<dyn Sandbox>> {
        if let Some(handle) = self.handles.lock().expect("handles lock").get(id) {
            return Ok(Arc::clone(handle));
        }
        let sandbox_id = SandboxId::try_new(id)
            .map_err(|error| Error::invalid_spec("sandbox_id", error.to_string()))?;
        let handle = self.provider.attach(&sandbox_id, None).await?;
        self.remember(&handle);
        Ok(handle)
    }

    fn remember(&self, handle: &Arc<dyn Sandbox>) {
        let mut handles = self.handles.lock().expect("handles lock");
        let id = handle.id().as_str();
        if !handles.contains_key(id) && handles.len() >= self.limits.cached_handles {
            if let Some(oldest) = handles.keys().next().cloned() {
                handles.remove(&oldest);
            }
        }
        handles.insert(id.to_owned(), Arc::clone(handle));
    }

    fn event_context(&self, request: Option<m::EventRequest>) -> Option<EventContext> {
        request.map(|request| {
            let mut context = EventContext::new(Arc::new(ProtocolEventObserver {
                outbound:      self.outbound.clone(),
                route_id:      request.route_id,
                failed:        self.delivery_failed.clone(),
                events_failed: Arc::clone(&self.events_failed),
            }));
            if let Some(correlation_id) = request.correlation_id {
                context = context.correlation_id(correlation_id);
            }
            context
        })
    }

    /// Opens the data channel a request named. Before `initialize` there
    /// is no transport to open it against, which is a protocol violation.
    async fn open_channel(
        &self,
        request: &ChannelRequest,
        permit: Option<Arc<OwnedSemaphorePermit>>,
    ) -> Result<Channel> {
        let _open = limits::acquire(&self.open_budget, "pending_opens")?;
        let transport = self.transport.get().ok_or_else(|| {
            Error::Transport(TransportError::new(
                "a data channel was requested before initialize",
            ))
        })?;
        let mut channel =
            time::timeout(self.limits.open_timeout, channel::open(transport, request))
                .await
                .map_err(|_| {
                    Error::Transport(TransportError::new("opening data channel timed out"))
                })??;
        channel.progress_timeout(self.limits.output_progress_timeout);
        if let Some(permit) = permit {
            channel.hold(permit);
        }
        Ok(channel)
    }
}

/// A spawned stdio process the plugin holds for the host: its control
/// handle and the stderr tail the host reads back at `wait`.
struct ServerStdio {
    handle:      Arc<dyn StdioProcessHandle>,
    stderr_tail: StderrTail,
    _permit:     Option<Arc<OwnedSemaphorePermit>>,
}

struct ServerPty {
    session: Arc<dyn sandbox_driver::PtySession>,
    _permit: Option<Arc<OwnedSemaphorePermit>>,
}

struct ProtocolEventObserver {
    outbound:      control::ControlSender,
    failed:        CancellationToken,
    events_failed: Arc<AtomicBool>,
    route_id:      String,
}

#[async_trait]
impl EventObserver for ProtocolEventObserver {
    async fn observe(&self, event: Event) {
        if self.events_failed.load(Ordering::SeqCst) {
            return;
        }
        let notification = Message::notification(
            m::HOST_EVENT,
            serde_json::to_value(m::HostEventNotification {
                event,
                route_id: Some(self.route_id.clone()),
            })
            .expect("host event notification contains serializable values"),
        );
        if self.outbound.send(&notification, false).is_err()
            && !self.events_failed.swap(true, Ordering::SeqCst)
        {
            let failure = Message::notification("host/event_failed", Value::Null);
            if self.outbound.send(&failure, true).is_err() {
                self.failed.cancel();
            }
        }
    }
}

#[derive(Debug)]
enum DispatchError {
    UnknownMethod,
    BadParams(serde_json::Error),
    App(Error),
}

impl From<Error> for DispatchError {
    fn from(error: Error) -> Self {
        Self::App(error)
    }
}

fn parse<T: DeserializeOwned>(params: Value) -> Result<T, DispatchError> {
    serde_json::from_value(params).map_err(DispatchError::BadParams)
}

fn to_value<T: Serialize>(value: &T) -> Result<Value, DispatchError> {
    serde_json::to_value(value).map_err(DispatchError::BadParams)
}

fn stdio(state: &ServerState, id: &str) -> Result<Arc<ServerStdio>> {
    state
        .stdios
        .lock()
        .expect("stdios lock")
        .get(id)
        .cloned()
        .ok_or_else(|| Error::invalid_spec("process_id", "unknown stdio process id"))
}

fn pty(state: &ServerState, id: &str) -> Result<Arc<dyn sandbox_driver::PtySession>> {
    state
        .ptys
        .lock()
        .expect("ptys lock")
        .get(id)
        .map(|entry| Arc::clone(&entry.session))
        .ok_or_else(|| Error::invalid_spec("pty_id", "unknown PTY id"))
}

type SharedWriter = Arc<AsyncMutex<FrameWriter<OwnedWriteHalf>>>;

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

fn log_frame_sink(writer: &SharedWriter) -> LogSink {
    let writer = Arc::clone(writer);
    Arc::new(move |chunk| {
        let writer = Arc::clone(&writer);
        Box::pin(async move { writer.lock().await.write(FrameKind::Stdout, &chunk).await })
    })
}

/// Ends the plugin's side of a channel; a failure here means the host is
/// gone, which the response will report too.
async fn finish_channel(writer: &SharedWriter) -> Result<()> {
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
async fn collect_stdin_frames(
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

/// Moves a file through the channel with one bounded pipe between the
/// provider and frame writer. Neither future outlives this operation.
async fn send_file(
    fs: &dyn Filesystem,
    path: &str,
    writer: &mut FrameWriter<OwnedWriteHalf>,
) -> Result<()> {
    let (mut pipe_writer, mut pipe_reader) = duplex(64 * 1024);
    let produce = async move {
        fs.read_to(path, &mut pipe_writer).await?;
        pipe_writer
            .shutdown()
            .await
            .map_err(|error| Error::io("closing file stream", error))
    };
    let send = async {
        let mut buffer = vec![0; 64 * 1024];
        loop {
            let read = pipe_reader
                .read(&mut buffer)
                .await
                .map_err(|error| Error::io("reading file stream", error))?;
            if read == 0 {
                return Ok(());
            }
            writer.write(FrameKind::Stdout, &buffer[..read]).await?;
        }
    };
    tokio::try_join!(produce, send)?;
    Ok(())
}

async fn receive_file(
    reader: &mut FrameReader<OwnedReadHalf>,
    output: &mut (dyn AsyncWrite + Unpin + Send),
    length: u64,
) -> Result<()> {
    let mut remaining = length;
    loop {
        match reader.read().await? {
            Some((FrameKind::Stdin, payload)) => {
                remaining = remaining.checked_sub(payload.len() as u64).ok_or_else(|| {
                    Error::invalid_spec("content_length", "file exceeds its declared length")
                })?;
                output
                    .write_all(&payload)
                    .await
                    .map_err(|error| Error::io("writing file stream", error))?;
            }
            Some((FrameKind::Eof, _)) | None => {
                if remaining != 0 {
                    return Err(Error::io(
                        "reading file stream",
                        io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "file ended before its declared length",
                        ),
                    ));
                }
                return Ok(());
            }
            Some((kind, _)) => {
                return Err(Error::invalid_spec(
                    "frame",
                    format!("unexpected {kind:?} frame on a write channel"),
                ));
            }
        }
    }
}

async fn write_file(
    fs: &dyn Filesystem,
    path: &str,
    reader: &mut FrameReader<OwnedReadHalf>,
    length: u64,
) -> Result<()> {
    let (mut pipe_writer, mut pipe_reader) = duplex(64 * 1024);
    let receive = async move {
        receive_file(reader, &mut pipe_writer, length).await?;
        pipe_writer
            .shutdown()
            .await
            .map_err(|error| Error::io("closing file stream", error))
    };
    tokio::try_join!(fs.write_from(path, &mut pipe_reader, length), receive)?;
    Ok(())
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
    }
}

async fn follow_logs<F>(state: &ServerState, stream_id: &str, follow: F) -> Result<()>
where
    F: Future<Output = Result<()>>,
{
    let cancel = {
        let mut streams = state.streams.lock().expect("streams lock");
        match streams.entry(stream_id.to_owned()) {
            Entry::Vacant(entry) => {
                let cancel = CancellationToken::new();
                entry.insert(cancel.clone());
                cancel
            }
            // A cancel request can overtake the task that handles the
            // follow request. Reuse its already-cancelled token.
            Entry::Occupied(entry) => entry.get().clone(),
        }
    };
    let outcome = tokio::select! {
        outcome = follow => outcome,
        () = cancel.cancelled() => Ok(()),
    };
    state
        .streams
        .lock()
        .expect("streams lock")
        .remove(stream_id);
    outcome
}

fn handle_info(handle: &Arc<dyn Sandbox>, status: SandboxStatus) -> m::HandleInfo {
    m::HandleInfo {
        status,
        capabilities: handle.capabilities().clone(),
        working_directory: handle.working_directory().to_owned(),
        runtime_directory: handle.runtime_directory().map(str::to_owned),
    }
}

#[tracing::instrument(skip_all, fields(method = method))]
async fn dispatch(
    state: &Arc<ServerState>,
    method: &str,
    params: Value,
    io_permit: Option<Arc<OwnedSemaphorePermit>>,
) -> Result<Value, DispatchError> {
    match method {
        m::INITIALIZE => {
            let version: u32 = parse(
                params
                    .get("protocol_version")
                    .cloned()
                    .unwrap_or(Value::Null),
            )?;
            if version != m::PROTOCOL_VERSION {
                return Err(DispatchError::App(Error::invalid_spec(
                    "protocol_version",
                    format!(
                        "plugin speaks protocol version {} but the host asked for {}",
                        m::PROTOCOL_VERSION,
                        version
                    ),
                )));
            }
            let request: m::InitializeParams = parse(params)?;
            if request.data_transport.max_frame_bytes != channel::MAX_FRAME_BYTES {
                return Err(DispatchError::App(Error::invalid_spec(
                    "data_transport.max_frame_bytes",
                    "must be 65536",
                )));
            }
            // A second initialize keeps the first transport: channels the
            // host is already waiting on were named against it.
            let _ = state.transport.set(request.data_transport);
            to_value(&m::InitializeResult {
                protocol_version: m::PROTOCOL_VERSION,
                provider:         m::ProviderInfo {
                    kind:    state.provider.kind().clone(),
                    version: env!("CARGO_PKG_VERSION").to_owned(),
                },
                capabilities:     state.provider.capabilities().clone(),
            })
        }
        m::SANDBOX_CREATE => {
            let request: m::CreateParams = parse(params)?;
            let events = state.event_context(request.events);
            let spec = SandboxSpec::try_from(request.spec)?;
            let handle = state.provider.create(&spec, events).await?;
            state.remember(&handle);
            let status = handle.describe().await?;
            to_value(&handle_info(&handle, status))
        }
        m::SANDBOX_ATTACH => {
            let request: m::AttachParams = parse(params)?;
            let sandbox_id = SandboxId::try_new(&request.sandbox_id)
                .map_err(|error| Error::invalid_spec("sandbox_id", error.to_string()))?;
            let events = state.event_context(request.events);
            let handle = state.provider.attach(&sandbox_id, events).await?;
            state.remember(&handle);
            let status = handle.describe().await?;
            to_value(&handle_info(&handle, status))
        }
        m::SANDBOX_LIST => {
            let request: m::ListParams = parse(params)?;
            let sandboxes = state.provider.list(&request.filter).await?;
            to_value(&m::ListResult { sandboxes })
        }
        m::SANDBOX_DESCRIBE => {
            let request: m::SandboxIdParams = parse(params)?;
            let status = state.sandbox(&request.sandbox_id).await?.describe().await?;
            to_value(&m::StatusResult { status })
        }
        m::SANDBOX_PLATFORM_INFO => {
            let request: m::SandboxIdParams = parse(params)?;
            let platform = state
                .sandbox(&request.sandbox_id)
                .await?
                .platform_info()
                .await?;
            to_value(&m::PlatformInfoResult { platform })
        }
        m::SANDBOX_ENVIRONMENT => {
            let request: m::SandboxIdParams = parse(params)?;
            let environment = state
                .sandbox(&request.sandbox_id)
                .await?
                .environment()
                .await?;
            to_value(&m::EnvironmentResult { environment })
        }
        m::SANDBOX_DELETE => {
            // Delete is a provider-level operation by id: no prior attach is
            // needed, and a sandbox no handle can be built for (stopped,
            // wedged, half-created) is still removed. A handle this
            // connection already holds is used so its event route sees the
            // delete.
            let request: m::AttachParams = parse(params)?;
            let remembered = state
                .handles
                .lock()
                .expect("handles lock")
                .get(&request.sandbox_id)
                .cloned();
            if let Some(handle) = remembered {
                handle.delete().await?;
            } else {
                let sandbox_id = SandboxId::try_new(&request.sandbox_id)
                    .map_err(|error| Error::invalid_spec("sandbox_id", error.to_string()))?;
                let events = state.event_context(request.events);
                state.provider.delete(&sandbox_id, events).await?;
            }
            state
                .handles
                .lock()
                .expect("handles lock")
                .remove(&request.sandbox_id);
            to_value(&m::Empty)
        }
        m::SANDBOX_START
        | m::SANDBOX_STOP
        | m::SANDBOX_PAUSE
        | m::SANDBOX_RESUME
        | m::SANDBOX_ARCHIVE
        | m::SANDBOX_RECOVER
        | m::SANDBOX_REFRESH_ACTIVITY => {
            let request: m::SandboxIdParams = parse(params)?;
            let handle = state.sandbox(&request.sandbox_id).await?;
            match method {
                m::SANDBOX_START => handle.start().await?,
                m::SANDBOX_STOP => handle.stop().await?,
                m::SANDBOX_PAUSE => handle.pause().await?,
                m::SANDBOX_RESUME => handle.resume().await?,
                m::SANDBOX_ARCHIVE => handle.archive().await?,
                m::SANDBOX_RECOVER => handle.recover().await?,
                _ => handle.refresh_activity().await?,
            }
            to_value(&m::Empty)
        }
        m::SANDBOX_UNDELETE => {
            let request: m::AttachParams = parse(params)?;
            let sandbox_id = SandboxId::try_new(&request.sandbox_id)
                .map_err(|error| Error::invalid_spec("sandbox_id", error.to_string()))?;
            let events = state.event_context(request.events);
            let handle = state.provider.undelete(&sandbox_id, events).await?;
            state.remember(&handle);
            let status = handle.describe().await?;
            to_value(&handle_info(&handle, status))
        }
        m::SANDBOX_FORK => {
            let request: m::ForkParams = parse(params)?;
            let handle = state.sandbox(&request.sandbox_id).await?;
            let options = request.options.try_into()?;
            let forked = handle.fork(&options).await?;
            state.remember(&forked);
            let status = forked.describe().await?;
            to_value(&handle_info(&forked, status))
        }
        m::SANDBOX_RESIZE => {
            let request: m::ResizeParams = parse(params)?;
            state
                .sandbox(&request.sandbox_id)
                .await?
                .resize(&request.resources)
                .await?;
            to_value(&m::Empty)
        }
        m::SANDBOX_SNAPSHOT => {
            let request: m::SnapshotParams = parse(params)?;
            let options = request.options.into();
            let snapshot = state
                .sandbox(&request.sandbox_id)
                .await?
                .snapshot(&options)
                .await?;
            to_value(&m::SnapshotResult {
                snapshot_id: snapshot.as_str().to_owned(),
            })
        }
        m::SANDBOX_SET_TIMERS => {
            let request: m::SetTimersParams = parse(params)?;
            state
                .sandbox(&request.sandbox_id)
                .await?
                .set_timers(&request.timers)
                .await?;
            to_value(&m::Empty)
        }
        m::SANDBOX_SET_LABELS => {
            let request: m::SetLabelsParams = parse(params)?;
            state
                .sandbox(&request.sandbox_id)
                .await?
                .set_labels(&request.labels)
                .await?;
            to_value(&m::Empty)
        }
        m::SANDBOX_UPDATE_NETWORK => {
            let request: m::UpdateNetworkParams = parse(params)?;
            state
                .sandbox(&request.sandbox_id)
                .await?
                .update_network(&request.network)
                .await?;
            to_value(&m::Empty)
        }
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
        m::EXEC_STDIO_OPEN => {
            let request: m::StdioOpenParams = parse(params)?;
            let channel = state
                .open_channel(&request.channel, io_permit.clone())
                .await?;
            let process = state
                .sandbox(&request.sandbox_id)
                .await?
                .exec()
                .spawn_stdio(&request.spec)
                .await?;
            let handle: Arc<dyn StdioProcessHandle> = Arc::from(process.handle);
            let entry_value = Arc::new(ServerStdio {
                handle:      Arc::clone(&handle),
                stderr_tail: process.stderr_tail,
                _permit:     io_permit.clone(),
            });
            let inserted = {
                let mut stdios = state.stdios.lock().expect("stdios lock");
                match stdios.entry(request.process_id.clone()) {
                    Entry::Vacant(entry) => {
                        entry.insert(entry_value);
                        true
                    }
                    Entry::Occupied(_) => false,
                }
            };
            if !inserted {
                handle.terminate().await;
                return Err(Error::invalid_spec("process_id", "duplicate stdio process id").into());
            }
            let Channel { mut reader, writer } = channel;
            let mut stdin = process.stdin;
            state.own(async move {
                // Anything but an input frame — the host's eof, a closed
                // connection, a stray kind — ends the process's stdin.
                while let Ok(Some((FrameKind::Stdin, payload))) = reader.read().await {
                    if stdin.write_all(&payload).await.is_err() {
                        break;
                    }
                }
                let _ = stdin.shutdown().await;
            });
            let mut stdout = process.stdout;
            state.own(async move {
                let mut writer = writer;
                let mut buffer = vec![0; 32 * 1024];
                loop {
                    match stdout.read(&mut buffer).await {
                        Ok(0) => break,
                        Err(_) => return,
                        Ok(read) => {
                            if writer
                                .write(FrameKind::Stdout, &buffer[..read])
                                .await
                                .is_err()
                            {
                                return;
                            }
                        }
                    }
                }
                let _ = writer.finish().await;
            });
            to_value(&m::Empty)
        }
        m::EXEC_STDIO_TERMINATE => {
            let request: m::StdioIdParams = parse(params)?;
            stdio(state, &request.process_id)?.handle.terminate().await;
            to_value(&m::Empty)
        }
        m::EXEC_STDIO_WAIT => {
            let request: m::StdioIdParams = parse(params)?;
            let process = stdio(state, &request.process_id)?;
            let (termination, exit_code) = process.handle.wait().await;
            state
                .stdios
                .lock()
                .expect("stdios lock")
                .remove(&request.process_id);
            to_value(&m::StdioWaitResult {
                termination,
                exit_code,
                stderr_tail: process.stderr_tail.to_string_lossy(),
            })
        }
        m::PTY_OPEN => {
            let request: m::PtyOpenParams = parse(params)?;
            let channel = state
                .open_channel(&request.channel, io_permit.clone())
                .await?;
            let handle = state.sandbox(&request.sandbox_id).await?;
            let pty = handle
                .pty()
                .ok_or_else(|| Error::unsupported(Capability::Pty))?
                .open(&request.options)
                .await?;
            let pty: Arc<dyn sandbox_driver::PtySession> = Arc::from(pty);
            let inserted = {
                let mut ptys = state.ptys.lock().expect("ptys lock");
                match ptys.entry(request.pty_id.clone()) {
                    Entry::Vacant(entry) => {
                        entry.insert(Arc::new(ServerPty {
                            session: Arc::clone(&pty),
                            _permit: io_permit.clone(),
                        }));
                        true
                    }
                    Entry::Occupied(_) => false,
                }
            };
            if !inserted {
                if let Err(error) = pty.close().await {
                    tracing::warn!(error = %error, "duplicate plugin PTY cleanup failed");
                }
                return Err(Error::invalid_spec("pty_id", "duplicate PTY id").into());
            }
            let Channel { mut reader, writer } = channel;
            let input_pty = Arc::clone(&pty);
            state.own(async move {
                while let Ok(Some((FrameKind::Stdin, payload))) = reader.read().await {
                    if input_pty.write_input(&payload).await.is_err() {
                        break;
                    }
                }
            });
            let output_pty = Arc::clone(&pty);
            state.own(async move {
                let mut writer = writer;
                loop {
                    match output_pty.read_output().await {
                        Ok(Some(chunk)) => {
                            if writer.write(FrameKind::Stdout, &chunk).await.is_err() {
                                return;
                            }
                        }
                        Ok(None) => break,
                        Err(_) => return,
                    }
                }
                let _ = writer.finish().await;
            });
            to_value(&m::Empty)
        }
        m::PTY_RESIZE => {
            let request: m::PtyResizeParams = parse(params)?;
            pty(state, &request.pty_id)?.resize(request.size).await?;
            to_value(&m::Empty)
        }
        m::PTY_CLOSE => {
            let request: m::PtyIdParams = parse(params)?;
            let session = state
                .ptys
                .lock()
                .expect("ptys lock")
                .remove(&request.pty_id);
            if let Some(session) = session {
                if let Err(error) = session.session.close().await {
                    state
                        .ptys
                        .lock()
                        .expect("ptys lock")
                        .insert(request.pty_id, session);
                    return Err(error.into());
                }
            }
            to_value(&m::Empty)
        }
        m::LOGS_FOLLOW => {
            let request: m::LogsFollowParams = parse(params)?;
            let handle = state.sandbox(&request.sandbox_id).await?;
            let logs = handle
                .logs()
                .ok_or_else(|| Error::unsupported(Capability::Logs))?;
            let channel = state.open_channel(&request.channel, io_permit).await?;
            let writer: SharedWriter = Arc::new(AsyncMutex::new(channel.writer));
            let outcome = follow_logs(
                state,
                &request.stream_id,
                logs.follow(request.source, log_frame_sink(&writer)),
            )
            .await;
            finish_channel(&writer).await?;
            outcome?;
            to_value(&m::Empty)
        }
        m::STREAM_CANCEL => {
            let request: m::StreamIdParams = parse(params)?;
            let cancel = {
                let mut streams = state.streams.lock().expect("streams lock");
                match streams.entry(request.stream_id) {
                    Entry::Occupied(entry) => entry.get().clone(),
                    Entry::Vacant(_) => return to_value(&m::Empty),
                }
            };
            cancel.cancel();
            to_value(&m::Empty)
        }
        m::FS_READ => {
            let request: m::FsReadParams = parse(params)?;
            let handle = state.sandbox(&request.sandbox_id).await?;
            let mut channel = state.open_channel(&request.channel, io_permit).await?;
            let outcome = async {
                if request.offset.is_some() || request.length.is_some() {
                    let content = handle
                        .fs()
                        .read_range(&request.path, request.offset.unwrap_or(0), request.length)
                        .await?;
                    channel.writer.write(FrameKind::Stdout, &content).await
                } else {
                    send_file(handle.fs(), &request.path, &mut channel.writer).await
                }
            }
            .await;
            let finished = channel.writer.finish().await;
            outcome?;
            finished?;
            to_value(&m::Empty)
        }
        m::FS_WRITE => {
            let request: m::FsWriteParams = parse(params)?;
            let handle = state.sandbox(&request.sandbox_id).await?;
            let mut channel = state.open_channel(&request.channel, io_permit).await?;
            let outcome = if let Some(length) = request.content_length.filter(|_| !request.append) {
                write_file(handle.fs(), &request.path, &mut channel.reader, length).await
            } else {
                let content = if let Some(length) = request.content_length {
                    if length > state.limits.buffered_value_bytes as u64 {
                        return Err(Error::LimitExceeded {
                            limit:     "buffered_value_bytes".into(),
                            max_bytes: state.limits.buffered_value_bytes,
                        }
                        .into());
                    }
                    let mut content = Vec::new();
                    receive_file(&mut channel.reader, &mut content, length).await?;
                    content
                } else {
                    collect_stdin_frames(&mut channel.reader, state.limits.buffered_value_bytes)
                        .await?
                };
                if request.append {
                    handle.fs().write_append(&request.path, &content).await
                } else {
                    handle.fs().write(&request.path, &content).await
                }
            };
            let _ = channel.writer.finish().await;
            outcome?;
            to_value(&m::Empty)
        }
        m::FS_DELETE => {
            let request: m::FsDeleteParams = parse(params)?;
            state
                .sandbox(&request.sandbox_id)
                .await?
                .fs()
                .delete(&request.path, request.recursive)
                .await?;
            to_value(&m::Empty)
        }
        m::FS_EXISTS => {
            let request: m::FsPathParams = parse(params)?;
            let exists = state
                .sandbox(&request.sandbox_id)
                .await?
                .fs()
                .exists(&request.path)
                .await?;
            to_value(&m::FsExistsResult { exists })
        }
        m::FS_METADATA => {
            let request: m::FsPathParams = parse(params)?;
            let metadata = state
                .sandbox(&request.sandbox_id)
                .await?
                .fs()
                .metadata(&request.path)
                .await?;
            to_value(&m::FsMetadataResult { metadata })
        }
        m::FS_LIST_DIR => {
            let request: m::FsListDirParams = parse(params)?;
            let entries = state
                .sandbox(&request.sandbox_id)
                .await?
                .fs()
                .list_dir(&request.path, request.depth)
                .await?;
            to_value(&m::FsListDirResult { entries })
        }
        m::FS_CREATE_DIR => {
            let request: m::FsPathParams = parse(params)?;
            state
                .sandbox(&request.sandbox_id)
                .await?
                .fs()
                .create_dir(&request.path)
                .await?;
            to_value(&m::Empty)
        }
        m::FS_RENAME => {
            let request: m::FsRenameParams = parse(params)?;
            state
                .sandbox(&request.sandbox_id)
                .await?
                .fs()
                .rename(&request.from, &request.to)
                .await?;
            to_value(&m::Empty)
        }
        m::FS_SET_PERMISSIONS => {
            let request: m::FsSetPermissionsParams = parse(params)?;
            state
                .sandbox(&request.sandbox_id)
                .await?
                .fs()
                .set_permissions(&request.path, request.mode)
                .await?;
            to_value(&m::Empty)
        }
        m::SNAPSHOT_CREATE => {
            let request: m::SnapshotCreateParams = parse(params)?;
            let events = state.event_context(request.events);
            let spec = request.spec.into();
            let service =
                state
                    .provider
                    .snapshots()
                    .ok_or(DispatchError::App(Error::unsupported(
                        Capability::Snapshots,
                    )))?;
            let id = service.create(&spec, events).await?;
            to_value(&m::SnapshotIdResult {
                snapshot_id: id.as_str().to_owned(),
            })
        }
        m::SNAPSHOT_GET => {
            let request: m::SnapshotIdParams = parse(params)?;
            let service =
                state
                    .provider
                    .snapshots()
                    .ok_or(DispatchError::App(Error::unsupported(
                        Capability::Snapshots,
                    )))?;
            let id = SnapshotId::try_new(&request.snapshot_id)
                .map_err(|error| Error::invalid_spec("snapshot_id", error.to_string()))?;
            let status = service.get(&id).await?;
            to_value(&m::SnapshotStatusResult { status })
        }
        m::SNAPSHOT_LIST => {
            let request: m::SnapshotListParams = parse(params)?;
            let service =
                state
                    .provider
                    .snapshots()
                    .ok_or(DispatchError::App(Error::unsupported(
                        Capability::Snapshots,
                    )))?;
            let snapshots = service.list(&request.filter).await?;
            to_value(&m::SnapshotListResult { snapshots })
        }
        m::SNAPSHOT_BUILD_LOGS => {
            let request: m::SnapshotBuildLogsParams = parse(params)?;
            let service = state
                .provider
                .snapshots()
                .ok_or_else(|| Error::unsupported(Capability::Snapshots))?;
            let id = SnapshotId::try_new(&request.snapshot_id)
                .map_err(|error| Error::invalid_spec("snapshot_id", error.to_string()))?;
            let channel = state.open_channel(&request.channel, io_permit).await?;
            let writer: SharedWriter = Arc::new(AsyncMutex::new(channel.writer));
            let outcome = follow_logs(
                state,
                &request.stream_id,
                service.build_logs(&id, request.follow, log_frame_sink(&writer)),
            )
            .await;
            finish_channel(&writer).await?;
            outcome?;
            to_value(&m::Empty)
        }
        m::SNAPSHOT_DELETE | m::SNAPSHOT_ACTIVATE | m::SNAPSHOT_DEACTIVATE => {
            let request: m::SnapshotIdParams = parse(params)?;
            let events = state.event_context(request.events);
            let service =
                state
                    .provider
                    .snapshots()
                    .ok_or(DispatchError::App(Error::unsupported(
                        Capability::Snapshots,
                    )))?;
            let id = SnapshotId::try_new(&request.snapshot_id)
                .map_err(|error| Error::invalid_spec("snapshot_id", error.to_string()))?;
            match method {
                m::SNAPSHOT_ACTIVATE => service.activate(&id, events).await?,
                m::SNAPSHOT_DEACTIVATE => service.deactivate(&id, events).await?,
                _ => service.delete(&id, events).await?,
            }
            to_value(&m::Empty)
        }
        m::TRANSPORT_DIAGNOSTICS => {
            let mut background = state.background.lock().expect("background tasks lock");
            background.retain(|task| !task.is_finished());
            to_value(&ServerDiagnostics {
                active_io:        state.limits.active_io - state.io_budget.available_permits(),
                pending_opens:    state.limits.pending_opens
                    - state.open_budget.available_permits(),
                execs:            state.execs.lock().expect("execs lock").len(),
                stdios:           state.stdios.lock().expect("stdios lock").len(),
                ptys:             state.ptys.lock().expect("ptys lock").len(),
                streams:          state.streams.lock().expect("streams lock").len(),
                cached_handles:   state.handles.lock().expect("handles lock").len(),
                background_tasks: background.len(),
                runtime_tasks:    RuntimeHandle::current().metrics().num_alive_tasks(),
            })
        }
        m::PROVIDER_HEALTH => {
            let health = state.provider.health().await?;
            to_value(&m::HealthResult { health })
        }
        m::VOLUME_CREATE => {
            let request: m::VolumeCreateParams = parse(params)?;
            let events = state.event_context(request.events);
            let service = state
                .provider
                .volumes()
                .ok_or(DispatchError::App(Error::unsupported(Capability::Volumes)))?;
            let id = service.create(&request.spec, events).await?;
            to_value(&m::VolumeIdResult {
                volume_id: id.as_str().to_owned(),
            })
        }
        m::VOLUME_GET => {
            let request: m::VolumeIdParams = parse(params)?;
            let service = state
                .provider
                .volumes()
                .ok_or(DispatchError::App(Error::unsupported(Capability::Volumes)))?;
            let id = VolumeId::try_new(&request.volume_id)
                .map_err(|error| Error::invalid_spec("volume_id", error.to_string()))?;
            let status = service.get(&id).await?;
            to_value(&m::VolumeStatusResult { status })
        }
        m::VOLUME_LIST => {
            let service = state
                .provider
                .volumes()
                .ok_or(DispatchError::App(Error::unsupported(Capability::Volumes)))?;
            let volumes = service.list().await?;
            to_value(&m::VolumeListResult { volumes })
        }
        m::VOLUME_DELETE => {
            let request: m::VolumeIdParams = parse(params)?;
            let events = state.event_context(request.events);
            let service = state
                .provider
                .volumes()
                .ok_or(DispatchError::App(Error::unsupported(Capability::Volumes)))?;
            let id = VolumeId::try_new(&request.volume_id)
                .map_err(|error| Error::invalid_spec("volume_id", error.to_string()))?;
            service.delete(&id, events).await?;
            to_value(&m::Empty)
        }
        m::ACCESS_PREVIEW_URL => {
            let request: m::PreviewUrlParams = parse(params)?;
            let handle = state.sandbox(&request.sandbox_id).await?;
            let facet = handle
                .preview_urls()
                .ok_or(DispatchError::App(Error::unsupported(
                    Capability::PreviewUrls,
                )))?;
            let preview = facet.preview_url(request.port).await?;
            to_value(&m::PreviewUrlResult { preview })
        }
        m::ACCESS_SIGNED_PREVIEW_URL => {
            let request: m::SignedPreviewUrlParams = parse(params)?;
            let handle = state.sandbox(&request.sandbox_id).await?;
            let facet = handle
                .preview_urls()
                .ok_or(DispatchError::App(Error::unsupported(
                    Capability::PreviewUrls,
                )))?;
            let preview = facet
                .signed_preview_url(request.port, Duration::from_millis(request.expires_in_ms))
                .await?;
            to_value(&m::PreviewUrlResult { preview })
        }
        m::ACCESS_SSH_CREATE => {
            let request: m::SshCreateParams = parse(params)?;
            let handle = state.sandbox(&request.sandbox_id).await?;
            if request.ttl_ms.is_some() && !handle.capabilities().access.ssh_ttl {
                return Err(Error::unsupported(Capability::SshTtl).into());
            }
            let facet = handle
                .ssh()
                .ok_or(DispatchError::App(Error::unsupported(Capability::Ssh)))?;
            let access = facet
                .ssh_access(request.ttl_ms.map(Duration::from_millis))
                .await?;
            to_value(&m::SshCreateResult { access })
        }
        m::ACCESS_SSH_REVOKE => {
            let request: m::SshRevokeParams = parse(params)?;
            let handle = state.sandbox(&request.sandbox_id).await?;
            if !handle.capabilities().access.ssh_revoke {
                return Err(Error::unsupported(Capability::SshRevoke).into());
            }
            let facet = handle
                .ssh()
                .ok_or(DispatchError::App(Error::unsupported(Capability::Ssh)))?;
            facet.revoke_ssh_access(&request.token).await?;
            to_value(&m::Empty)
        }
        m::ACCESS_WEB_TERMINAL => {
            let request: m::SandboxIdParams = parse(params)?;
            let handle = state.sandbox(&request.sandbox_id).await?;
            let facet = handle
                .web_terminal()
                .ok_or_else(|| Error::unsupported(Capability::WebTerminalAccess))?;
            to_value(&m::WebTerminalResult {
                url: facet.web_terminal_url().await?,
            })
        }
        m::ACCESS_VNC => {
            let request: m::SandboxIdParams = parse(params)?;
            let handle = state.sandbox(&request.sandbox_id).await?;
            let facet = handle
                .vnc()
                .ok_or_else(|| Error::unsupported(Capability::VncAccess))?;
            to_value(&m::VncResult {
                connection: facet.vnc_connection().await?,
            })
        }
        _ => Err(DispatchError::UnknownMethod),
    }
}

#[cfg(test)]
mod file_transfer_tests {
    use tokio::net::UnixStream;

    use super::*;

    #[tokio::test]
    async fn write_channel_enforces_the_declared_content_length() {
        for length in [0, 4, 5, 6] {
            let (host, plugin) = UnixStream::pair().expect("channel");
            let (_, host_write) = host.into_split();
            let (plugin_read, _) = plugin.into_split();
            let mut writer = FrameWriter::new(host_write, channel::MAX_FRAME_BYTES);
            let mut reader = FrameReader::new(plugin_read, channel::MAX_FRAME_BYTES);
            writer
                .write(FrameKind::Stdin, b"bytes")
                .await
                .expect("content");
            writer.finish().await.expect("end of content");
            let mut content = Vec::new();
            let outcome = receive_file(&mut reader, &mut content, length).await;
            match length {
                5 => {
                    outcome.expect("exact content length");
                    assert_eq!(content, b"bytes");
                }
                6 => assert!(matches!(outcome, Err(Error::Io { source, .. })
                    if source.kind() == io::ErrorKind::UnexpectedEof)),
                _ => assert!(matches!(outcome, Err(Error::InvalidSpec { field, .. })
                    if field == "content_length")),
            }
        }
    }
}
