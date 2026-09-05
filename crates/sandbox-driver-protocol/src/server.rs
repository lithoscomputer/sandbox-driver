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
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use async_trait::async_trait;
use sandbox_driver::{
    Capability, Error, Event, EventContext, EventObserver, ExecControls, ExecStreamingResult,
    LogSink, OutputSink, OutputStream, Result, Sandbox, SandboxId, SandboxProvider, SandboxSpec,
    SandboxStatus, SnapshotId, StderrTail, StdinSource, StdioProcessHandle, StopLevel,
    TransportError, VolumeId,
};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;
use tokio::io::{
    AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, duplex, stdin,
    stdout,
};
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::{Mutex as AsyncMutex, mpsc};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tokio_util::task::AbortOnDropHandle;

use crate::channel::{
    self, Channel, ChannelRequest, DataTransport, FrameKind, FrameReader, FrameWriter,
};
use crate::methods as m;
use crate::wire::{CODE_INVALID_REQUEST, CODE_METHOD_NOT_FOUND, Message, WireError};

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
    let (outbound, mut outbound_rx) = mpsc::channel::<Message>(256);
    let mut writer_task = tokio::spawn(async move {
        let mut writer = writer;
        while let Some(message) = outbound_rx.recv().await {
            let mut line = serde_json::to_string(&message).map_err(|error| {
                Error::Transport(TransportError::with_source(
                    "encoding plugin response",
                    error,
                ))
            })?;
            line.push('\n');
            writer.write_all(line.as_bytes()).await.map_err(|error| {
                Error::Transport(TransportError::with_source(
                    "writing plugin response",
                    error,
                ))
            })?;
        }
        writer.shutdown().await.map_err(|error| {
            Error::Transport(TransportError::with_source(
                "closing plugin response transport",
                error,
            ))
        })
    });

    let state = Arc::new(ServerState {
        provider,
        transport: OnceLock::new(),
        handles: Mutex::new(HashMap::new()),
        execs: Mutex::new(HashMap::new()),
        stdios: Mutex::new(HashMap::new()),
        ptys: Mutex::new(HashMap::new()),
        streams: Mutex::new(HashMap::new()),
        outbound: outbound.clone(),
    });

    let shutdown = CancellationToken::new();
    let mut lines = BufReader::new(reader).lines();
    let mut writer_finished = false;
    let outcome = loop {
        let line = tokio::select! {
            line = lines.next_line() => line,
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
            () = shutdown.cancelled() => break Ok(()),
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
        if line.trim().is_empty() {
            continue;
        }
        let message: Message = match serde_json::from_str(&line) {
            Ok(message) => message,
            Err(error) => {
                let _ = outbound
                    .send(Message::error_response(0, WireError {
                        code:    CODE_INVALID_REQUEST,
                        message: format!("malformed message: {error}"),
                        data:    None,
                    }))
                    .await;
                continue;
            }
        };
        let (Some(id), Some(method)) = (message.id, message.method.clone()) else {
            // There are no host→plugin notifications; ignore.
            continue;
        };
        if method == m::SHUTDOWN {
            if let Err(error) = outbound.send(Message::response(id, Value::Null)).await {
                break Err(Error::Transport(TransportError::with_source(
                    "sending plugin shutdown response",
                    error,
                )));
            }
            shutdown.cancel();
            continue;
        }
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            let params = message.params.unwrap_or(Value::Null);
            let reply = match dispatch(&state, &method, params).await {
                Ok(result) => Message::response(id, result),
                Err(DispatchError::UnknownMethod) => Message::error_response(id, WireError {
                    code:    CODE_METHOD_NOT_FOUND,
                    message: format!("unknown method {method}"),
                    data:    None,
                }),
                Err(DispatchError::BadParams(error)) => Message::error_response(id, WireError {
                    code:    CODE_INVALID_REQUEST,
                    message: format!("invalid params for {method}: {error}"),
                    data:    None,
                }),
                Err(DispatchError::App(error)) => {
                    Message::error_response(id, WireError::from_error(&error))
                }
            };
            if state.outbound.send(reply).await.is_err() {
                tracing::warn!(request_id = id, method = %method, "plugin response queue closed");
            }
        });
    };

    state.close_sessions().await;
    drop(outbound);
    drop(state);
    let writer_outcome = if writer_finished {
        Ok(())
    } else {
        writer_task.await.map_err(|error| {
            Error::Transport(TransportError::with_source(
                "joining plugin response writer",
                error,
            ))
        })?
    };
    outcome?;
    writer_outcome
}

struct ServerState {
    provider:  Arc<dyn SandboxProvider>,
    /// Set by `initialize`; every data channel opens against it.
    transport: OnceLock<DataTransport>,
    handles:   Mutex<HashMap<String, Arc<dyn Sandbox>>>,
    /// Per in-flight exec: its `term` and `kill` tokens, in that order.
    execs:     Mutex<HashMap<String, (CancellationToken, CancellationToken)>>,
    stdios:    Mutex<HashMap<String, Arc<ServerStdio>>>,
    ptys:      Mutex<HashMap<String, Arc<dyn sandbox_driver::PtySession>>>,
    streams:   Mutex<HashMap<String, CancellationToken>>,
    outbound:  mpsc::Sender<Message>,
}

impl ServerState {
    async fn close_sessions(&self) {
        // A closing connection has no caller left to escalate, so every
        // in-flight exec is killed outright.
        let execs = self
            .execs
            .lock()
            .expect("execs lock")
            .drain()
            .map(|(_, (_, kill))| kill)
            .collect::<Vec<_>>();
        let streams = self
            .streams
            .lock()
            .expect("streams lock")
            .drain()
            .map(|(_, token)| token)
            .collect::<Vec<_>>();
        for token in execs.into_iter().chain(streams) {
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
            if let Err(error) = session.close().await {
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
        self.handles
            .lock()
            .expect("handles lock")
            .insert(id.to_owned(), Arc::clone(&handle));
        Ok(handle)
    }

    fn remember(&self, handle: &Arc<dyn Sandbox>) {
        self.handles
            .lock()
            .expect("handles lock")
            .insert(handle.id().as_str().to_owned(), Arc::clone(handle));
    }

    fn event_context(&self, request: Option<m::EventRequest>) -> Option<EventContext> {
        request.map(|request| {
            let mut context = EventContext::new(Arc::new(ProtocolEventObserver {
                outbound: self.outbound.clone(),
                route_id: request.route_id,
            }));
            if let Some(correlation_id) = request.correlation_id {
                context = context.correlation_id(correlation_id);
            }
            context
        })
    }

    /// Opens the data channel a request named. Before `initialize` there
    /// is no transport to open it against, which is a protocol violation.
    async fn open_channel(&self, request: &ChannelRequest) -> Result<Channel> {
        let transport = self.transport.get().ok_or_else(|| {
            Error::Transport(TransportError::new(
                "a data channel was requested before initialize",
            ))
        })?;
        channel::open(transport, request).await
    }
}

/// A spawned stdio process the plugin holds for the host: its control
/// handle and the stderr tail the host reads back at `wait`.
struct ServerStdio {
    handle:      Arc<dyn StdioProcessHandle>,
    stderr_tail: StderrTail,
}

struct ProtocolEventObserver {
    outbound: mpsc::Sender<Message>,
    route_id: String,
}

#[async_trait]
impl EventObserver for ProtocolEventObserver {
    async fn observe(&self, event: Event) {
        let notification = Message::notification(
            m::HOST_EVENT,
            serde_json::to_value(m::HostEventNotification {
                event,
                route_id: Some(self.route_id.clone()),
            })
            .expect("host event notification contains serializable values"),
        );
        if self.outbound.send(notification).await.is_err() {
            tracing::debug!("host event notification transport closed");
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
        .cloned()
        .ok_or_else(|| Error::invalid_spec("pty_id", "unknown PTY id"))
}

type SharedWriter = Arc<AsyncMutex<FrameWriter<OwnedWriteHalf>>>;

/// A sink that writes every chunk as one frame of its stream, awaiting
/// the connection: a slow host consumer backpressures exactly this
/// operation.
fn frame_sink(writer: &SharedWriter) -> OutputSink {
    let writer = Arc::clone(writer);
    Arc::new(move |stream, chunk| {
        let writer = Arc::clone(&writer);
        Box::pin(async move {
            let kind = match stream {
                OutputStream::Stdout => FrameKind::Stdout,
                OutputStream::Stderr => FrameKind::Stderr,
            };
            writer.lock().await.write(kind, &chunk).await
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
async fn finish_channel(writer: &SharedWriter) {
    if let Err(error) = writer.lock().await.finish().await {
        tracing::debug!(error = %error, "data channel eof was not delivered");
    }
}

/// Pumps the host's `Stdin` frames into `sink` until its `Eof`. The
/// duplex's writer half closing is the command's end-of-file.
fn pump_stdin_frames(mut reader: FrameReader<OwnedReadHalf>) -> (StdinSource, JoinHandle<()>) {
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
                    tracing::warn!(?kind, "unexpected frame on an input channel");
                    break;
                }
                Err(error) => {
                    tracing::debug!(error = %error, "input channel read failed");
                    break;
                }
            }
        }
        let _ = writer.shutdown().await;
    });
    (StdinSource::new(pipe), task)
}

/// Reads the host's `Stdin` frames to `Eof` and returns the bytes.
async fn collect_stdin_frames(reader: &mut FrameReader<OwnedReadHalf>) -> Result<Vec<u8>> {
    let mut content = Vec::new();
    loop {
        match reader.read().await? {
            Some((FrameKind::Stdin, payload)) => content.extend(payload),
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
    fn new(state: &'a ServerState, id: &'a str) -> Self {
        let term = CancellationToken::new();
        let kill = CancellationToken::new();
        state
            .execs
            .lock()
            .expect("execs lock")
            .insert(id.to_owned(), (term.clone(), kill.clone()));
        Self {
            state,
            id,
            term,
            kill,
        }
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
    let (stdin_source, stdin_task) = if stdin {
        let (source, task) = pump_stdin_frames(reader);
        (Some(source), Some(AbortOnDropHandle::new(task)))
    } else {
        (None, None)
    };
    let controls = ExecControls {
        term:                  Some(registration.term.clone()),
        kill:                  Some(registration.kill.clone()),
        stdin:                 stdin_source,
        sink:                  Some(frame_sink(&writer)),
        // The host captures the frames. Retaining another copy here
        // would grow memory with output the response never contains.
        retained_output_limit: Some(0),
    };
    let outcome = run(controls).await;
    if let Some(task) = stdin_task {
        task.abort();
    }
    finish_channel(&writer).await;
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
            if request.data_transport.max_frame_bytes == 0 {
                return Err(DispatchError::App(Error::invalid_spec(
                    "data_transport.max_frame_bytes",
                    "must be positive",
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
            let registration = ExecRegistration::new(state, &request.exec_id);
            let mut channel = state.open_channel(&request.channel).await?;
            // A provider without streamed stdin takes the input as the
            // spec's fixed bytes, so the host's stream still reaches the
            // command; one without any stdin then rejects it honestly.
            let stream_stdin = request.stdin && handle.capabilities().exec.stdin_stream;
            if request.stdin && !stream_stdin {
                spec.stdin = Some(collect_stdin_frames(&mut channel.reader).await?);
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
            let registration = ExecRegistration::new(state, &request.exec_id);
            let channel = state.open_channel(&request.channel).await?;
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
            let channel = match state.open_channel(&request.channel).await {
                Ok(channel) => channel,
                Err(error) => {
                    state
                        .stdios
                        .lock()
                        .expect("stdios lock")
                        .remove(&request.process_id);
                    handle.terminate().await;
                    return Err(error.into());
                }
            };
            let Channel { mut reader, writer } = channel;
            let mut stdin = process.stdin;
            tokio::spawn(async move {
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
            tokio::spawn(async move {
                let mut writer = writer;
                let mut buffer = vec![0; 32 * 1024];
                loop {
                    match stdout.read(&mut buffer).await {
                        Ok(0) | Err(_) => break,
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
                        entry.insert(Arc::clone(&pty));
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
            let channel = match state.open_channel(&request.channel).await {
                Ok(channel) => channel,
                Err(error) => {
                    state
                        .ptys
                        .lock()
                        .expect("ptys lock")
                        .remove(&request.pty_id);
                    let _ = pty.close().await;
                    return Err(error.into());
                }
            };
            let Channel { mut reader, writer } = channel;
            let input_pty = Arc::clone(&pty);
            tokio::spawn(async move {
                while let Ok(Some((FrameKind::Stdin, payload))) = reader.read().await {
                    if input_pty.write_input(&payload).await.is_err() {
                        break;
                    }
                }
            });
            let output_pty = Arc::clone(&pty);
            tokio::spawn(async move {
                let mut writer = writer;
                while let Ok(Some(chunk)) = output_pty.read_output().await {
                    if writer.write(FrameKind::Stdout, &chunk).await.is_err() {
                        return;
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
                session.close().await?;
            }
            to_value(&m::Empty)
        }
        m::LOGS_FOLLOW => {
            let request: m::LogsFollowParams = parse(params)?;
            let handle = state.sandbox(&request.sandbox_id).await?;
            let logs = handle
                .logs()
                .ok_or_else(|| Error::unsupported(Capability::Logs))?;
            let channel = state.open_channel(&request.channel).await?;
            let writer: SharedWriter = Arc::new(AsyncMutex::new(channel.writer));
            let outcome = follow_logs(
                state,
                &request.stream_id,
                logs.follow(request.source, log_frame_sink(&writer)),
            )
            .await;
            finish_channel(&writer).await;
            outcome?;
            to_value(&m::Empty)
        }
        m::STREAM_CANCEL => {
            let request: m::StreamIdParams = parse(params)?;
            let cancel = {
                let mut streams = state.streams.lock().expect("streams lock");
                match streams.entry(request.stream_id) {
                    Entry::Occupied(entry) => entry.get().clone(),
                    Entry::Vacant(entry) => {
                        let cancel = CancellationToken::new();
                        entry.insert(cancel.clone());
                        cancel
                    }
                }
            };
            cancel.cancel();
            to_value(&m::Empty)
        }
        m::FS_READ => {
            let request: m::FsReadParams = parse(params)?;
            let handle = state.sandbox(&request.sandbox_id).await?;
            let mut channel = state.open_channel(&request.channel).await?;
            let content = if request.offset.is_some() || request.length.is_some() {
                handle
                    .fs()
                    .read_range(&request.path, request.offset.unwrap_or(0), request.length)
                    .await
            } else {
                handle.fs().read(&request.path).await
            };
            let content = match content {
                Ok(content) => content,
                Err(error) => {
                    // The host learns of the failure from the response; the
                    // channel just ends.
                    let _ = channel.writer.finish().await;
                    return Err(error.into());
                }
            };
            channel.writer.write(FrameKind::Stdout, &content).await?;
            channel.writer.finish().await?;
            to_value(&m::Empty)
        }
        m::FS_WRITE => {
            let request: m::FsWriteParams = parse(params)?;
            let handle = state.sandbox(&request.sandbox_id).await?;
            let mut channel = state.open_channel(&request.channel).await?;
            let content = collect_stdin_frames(&mut channel.reader).await?;
            let outcome = if request.append {
                handle.fs().write_append(&request.path, &content).await
            } else {
                handle.fs().write(&request.path, &content).await
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
            let channel = state.open_channel(&request.channel).await?;
            let writer: SharedWriter = Arc::new(AsyncMutex::new(channel.writer));
            let outcome = follow_logs(
                state,
                &request.stream_id,
                service.build_logs(&id, request.follow, log_frame_sink(&writer)),
            )
            .await;
            finish_channel(&writer).await;
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
