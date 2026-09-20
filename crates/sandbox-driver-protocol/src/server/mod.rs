//! Serves any [`SandboxProvider`] over newline-delimited JSON-RPC.
//!
//! Every request is handled in its own task, so a slow call never blocks
//! its siblings (the interleaving requirement from the design). One
//! writer task owns the control stream; events cross as notifications and
//! every byte stream rides a data channel the plugin opens back to the
//! host ([`crate::channel`]).

use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use async_trait::async_trait;
use sandbox_driver::{
    Capability, Error, Event, EventContext, EventObserver, Result, Sandbox, SandboxId,
    SandboxProvider, SnapshotId, SnapshotProvider, TransportError, VolumeId, VolumeProvider,
};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, BufReader, stdin, stdout};
use tokio::runtime::Handle as RuntimeHandle;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinSet;
use tokio::time;
use tokio_util::sync::CancellationToken;
use tokio_util::task::AbortOnDropHandle;

use self::registry::Registry;
use self::sessions::{ServerPty, ServerStdio};
use crate::channel::{self, Channel, ChannelRequest, DataTransport};
use crate::wire::{
    CODE_APPLICATION, CODE_INVALID_REQUEST, CODE_METHOD_NOT_FOUND, Message, WireError,
};
use crate::{ServerDiagnostics, TransportLimits, control, limits, methods as m};

mod access;
mod exec;
mod fs;
mod registry;
mod sandbox;
mod services;
mod sessions;

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
    let (outbound, outbound_rx) = control::queue(&limits);
    let mut writer_task = spawn_control_writer(writer, outbound_rx, limits.output_progress_timeout);
    let state = Arc::new(ServerState::new(provider, outbound.clone(), limits));
    let limits = &state.limits;
    let mut requests = JoinSet::new();

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
        let admission = match state.admit(&method) {
            Ok(admission) => admission,
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
            if state
                .streams
                .try_insert(stream.clone(), state.exec_shutdown.child_token())
                .is_err()
            {
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
        }
        requests.spawn(handle_request(
            Arc::clone(&state),
            id,
            method,
            message.params.unwrap_or(Value::Null),
            admission,
            stream_id,
        ));
    };

    shutdown(
        state,
        requests,
        outbound,
        writer_task,
        writer_finished,
        outcome,
    )
    .await
}

/// Owns the control stream: writes each queued message under a progress
/// deadline, then closes the writer once every sender is gone.
fn spawn_control_writer(
    writer: impl AsyncWrite + Unpin + Send + 'static,
    mut outbound_rx: control::ControlReceiver,
    progress_timeout: Duration,
) -> AbortOnDropHandle<Result<()>> {
    AbortOnDropHandle::new(tokio::spawn(async move {
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
    }))
}

/// What one admitted request holds until its reply is delivered: its
/// request slot and, for a method that moves bytes, its I/O slot.
struct Admission {
    priority:       bool,
    request_permit: OwnedSemaphorePermit,
    io_permit:      Option<Arc<OwnedSemaphorePermit>>,
}

/// Runs one admitted request to its reply and delivers the reply. A reply
/// the control queue cannot take is downgraded to its limit error; a
/// reply that cannot be delivered at all fails the connection, because
/// the host can no longer tell which provider effects happened.
async fn handle_request(
    state: Arc<ServerState>,
    id: u64,
    method: String,
    params: Value,
    admission: Admission,
    stream_id: Option<String>,
) {
    let _request_permit = admission.request_permit;
    let reply = match dispatch(&state, &method, params, admission.io_permit).await {
        Ok(result) => Message::response(id, result),
        Err(error) => Message::error_response(id, error.into_wire(&method)),
    };
    if let Some(stream) = stream_id {
        state.streams.remove(&stream);
    }
    let delivery = state
        .outbound
        .deliver(
            &reply,
            admission.priority,
            state.limits.output_progress_timeout,
        )
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
}

/// Ends the connection in a fixed order. Sessions the plugin holds are
/// closed and in-flight requests get the shutdown budget to finish; what
/// remains is aborted. Background pumps are dropped, then the control
/// queue's last senders, so the writer drains and exits on its own; the
/// writer is joined last. The serve loop's own outcome outranks a
/// cleanup timeout, which outranks a writer failure.
async fn shutdown(
    state: Arc<ServerState>,
    mut requests: JoinSet<()>,
    outbound: control::ControlSender,
    mut writer_task: AbortOnDropHandle<Result<()>>,
    writer_finished: bool,
    outcome: Result<()>,
) -> Result<()> {
    let shutdown_timeout = state.limits.shutdown_timeout;
    let cleanup = time::timeout(shutdown_timeout, async {
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
        time::timeout(shutdown_timeout, &mut writer_task)
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
    request_budget:  Arc<Semaphore>,
    reserved_budget: Arc<Semaphore>,
    open_budget:     Arc<Semaphore>,
    io_budget:       Arc<Semaphore>,
    handles:         Registry<Arc<dyn Sandbox>>,
    /// Per in-flight exec: its `term` and `kill` tokens, in that order.
    execs:           Registry<(CancellationToken, CancellationToken)>,
    exec_shutdown:   CancellationToken,
    stdios:          Registry<Arc<ServerStdio>>,
    ptys:            Registry<Arc<ServerPty>>,
    streams:         Registry<CancellationToken>,
    outbound:        control::ControlSender,
    limits:          TransportLimits,
    delivery_failed: CancellationToken,
    events_failed:   Arc<AtomicBool>,
    background:      Mutex<Vec<AbortOnDropHandle<()>>>,
}

impl ServerState {
    fn new(
        provider: Arc<dyn SandboxProvider>,
        outbound: control::ControlSender,
        limits: TransportLimits,
    ) -> Self {
        Self {
            provider,
            transport: OnceLock::new(),
            request_budget: Arc::new(Semaphore::new(limits.provider_requests)),
            reserved_budget: Arc::new(Semaphore::new(limits.reserved_requests)),
            open_budget: Arc::new(Semaphore::new(limits.pending_opens)),
            io_budget: Arc::new(Semaphore::new(limits.active_io)),
            handles: Registry::default(),
            execs: Registry::default(),
            exec_shutdown: CancellationToken::new(),
            stdios: Registry::default(),
            ptys: Registry::default(),
            streams: Registry::default(),
            outbound,
            limits,
            delivery_failed: CancellationToken::new(),
            events_failed: Arc::new(AtomicBool::new(false)),
            background: Mutex::new(Vec::new()),
        }
    }

    /// Admits a request or rejects it at once; admission never waits.
    /// Reserved methods draw on their own budget so a stop or cancel
    /// still gets through when ordinary requests have filled theirs.
    fn admit(&self, method: &str) -> Result<Admission> {
        let priority = limits::reserved(method);
        let request_permit = limits::acquire(
            if priority {
                &self.reserved_budget
            } else {
                &self.request_budget
            },
            if priority {
                "reserved_requests"
            } else {
                "provider_requests"
            },
        )?;
        let io_permit = if limits::uses_io(method) {
            Some(Arc::new(limits::acquire(&self.io_budget, "active_io")?))
        } else {
            None
        };
        Ok(Admission {
            priority,
            request_permit,
            io_permit,
        })
    }

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
        self.execs.drain();
        for token in self.streams.drain() {
            token.cancel();
        }

        for process in self.stdios.drain() {
            process.handle.terminate().await;
        }

        for session in self.ptys.drain() {
            if let Err(error) = session.session.close().await {
                tracing::warn!(error = %error, "plugin PTY cleanup failed");
            }
        }
    }

    async fn sandbox(&self, id: &str) -> Result<Arc<dyn Sandbox>> {
        if let Some(handle) = self.handles.get(id) {
            return Ok(handle);
        }
        let handle = self.provider.attach(&sandbox_id(id)?, None).await?;
        self.remember(&handle);
        Ok(handle)
    }

    fn remember(&self, handle: &Arc<dyn Sandbox>) {
        self.handles.insert_bounded(
            handle.id().as_str().to_owned(),
            Arc::clone(handle),
            self.limits.cached_handles,
        );
    }

    fn snapshots(&self) -> Result<&dyn SnapshotProvider> {
        self.provider
            .snapshots()
            .ok_or_else(|| Error::unsupported(Capability::Snapshots))
    }

    fn volumes(&self) -> Result<&dyn VolumeProvider> {
        self.provider
            .volumes()
            .ok_or_else(|| Error::unsupported(Capability::Volumes))
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

/// The wire ids hosts send, checked into the typed ids providers take.
fn sandbox_id(id: &str) -> Result<SandboxId> {
    SandboxId::try_new(id).map_err(|error| Error::invalid_spec("sandbox_id", error.to_string()))
}

fn snapshot_id(id: &str) -> Result<SnapshotId> {
    SnapshotId::try_new(id).map_err(|error| Error::invalid_spec("snapshot_id", error.to_string()))
}

fn volume_id(id: &str) -> Result<VolumeId> {
    VolumeId::try_new(id).map_err(|error| Error::invalid_spec("volume_id", error.to_string()))
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
    /// The host's params did not decode.
    BadParams(serde_json::Error),
    /// The plugin's own result did not encode: a plugin bug, never the
    /// host's fault.
    Internal(serde_json::Error),
    App(Error),
}

impl From<Error> for DispatchError {
    fn from(error: Error) -> Self {
        Self::App(error)
    }
}

impl DispatchError {
    /// The JSON-RPC error a failed `method` answers with.
    fn into_wire(self, method: &str) -> WireError {
        match self {
            Self::UnknownMethod => WireError {
                code:    CODE_METHOD_NOT_FOUND,
                message: format!("unknown method {method}"),
                data:    None,
            },
            Self::BadParams(error) => WireError {
                code:    CODE_INVALID_REQUEST,
                message: format!(
                    "invalid params for {method} at line {} column {}",
                    error.line(),
                    error.column()
                ),
                data:    None,
            },
            Self::Internal(error) => WireError {
                code:    CODE_APPLICATION,
                message: format!("plugin failed to encode the {method} result: {error}"),
                data:    None,
            },
            Self::App(error) => WireError::from_error(&error),
        }
    }
}

fn parse<T: DeserializeOwned>(params: Value) -> Result<T, DispatchError> {
    serde_json::from_value(params).map_err(DispatchError::BadParams)
}

fn to_value<T: Serialize>(value: &T) -> Result<Value, DispatchError> {
    serde_json::to_value(value).map_err(DispatchError::Internal)
}

#[tracing::instrument(skip_all, fields(method = method))]
async fn dispatch(
    state: &Arc<ServerState>,
    method: &str,
    params: Value,
    io_permit: Option<Arc<OwnedSemaphorePermit>>,
) -> Result<Value, DispatchError> {
    let Some((namespace, _)) = method.split_once('/') else {
        return match method {
            m::INITIALIZE => initialize(state, params),
            _ => Err(DispatchError::UnknownMethod),
        };
    };
    match namespace {
        "sandbox" => sandbox::dispatch(state, method, params).await,
        "exec" => match method {
            m::EXEC_STDIO_OPEN | m::EXEC_STDIO_TERMINATE | m::EXEC_STDIO_WAIT => {
                sessions::dispatch(state, method, params, io_permit).await
            }
            _ => exec::dispatch(state, method, params, io_permit).await,
        },
        "one_shot" => exec::dispatch(state, method, params, io_permit).await,
        "pty" => sessions::dispatch(state, method, params, io_permit).await,
        "fs" => fs::dispatch(state, method, params, io_permit).await,
        "git" | "access" => access::dispatch(state, method, params).await,
        "logs" | "stream" | "snapshot" | "volume" => {
            services::dispatch(state, method, params, io_permit).await
        }
        "transport" | "provider" => match method {
            m::TRANSPORT_DIAGNOSTICS => {
                let mut background = state.background.lock().expect("background tasks lock");
                background.retain(|task| !task.is_finished());
                to_value(&ServerDiagnostics {
                    active_io:        state.limits.active_io - state.io_budget.available_permits(),
                    pending_opens:    state.limits.pending_opens
                        - state.open_budget.available_permits(),
                    execs:            state.execs.len(),
                    stdios:           state.stdios.len(),
                    ptys:             state.ptys.len(),
                    streams:          state.streams.len(),
                    cached_handles:   state.handles.len(),
                    background_tasks: background.len(),
                    runtime_tasks:    RuntimeHandle::current().metrics().num_alive_tasks(),
                })
            }
            m::PROVIDER_HEALTH => {
                let health = state.provider.health().await?;
                to_value(&m::HealthResult { health })
            }
            _ => Err(DispatchError::UnknownMethod),
        },
        _ => Err(DispatchError::UnknownMethod),
    }
}

fn initialize(state: &ServerState, params: Value) -> Result<Value, DispatchError> {
    let version: u32 = parse(
        params
            .get("protocol_version")
            .cloned()
            .unwrap_or(Value::Null),
    )?;
    if version != m::PROTOCOL_VERSION {
        return Err(Error::invalid_spec(
            "protocol_version",
            format!(
                "plugin speaks protocol version {} but the host asked for {}",
                m::PROTOCOL_VERSION,
                version
            ),
        )
        .into());
    }
    let request: m::InitializeParams = parse(params)?;
    if request.data_transport.max_frame_bytes != channel::MAX_FRAME_BYTES {
        return Err(Error::invalid_spec("data_transport.max_frame_bytes", "must be 65536").into());
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

#[cfg(test)]
mod tests {
    use serde::Serializer;

    use super::*;

    struct Unencodable;

    impl Serialize for Unencodable {
        fn serialize<S: Serializer>(&self, _: S) -> Result<S::Ok, S::Error> {
            Err(serde::ser::Error::custom(
                "the plugin built a result it cannot encode",
            ))
        }
    }

    #[test]
    fn a_result_the_plugin_cannot_encode_is_its_own_failure_not_the_hosts() {
        let Err(error) = to_value(&Unencodable) else {
            panic!("encoding must fail");
        };
        assert!(matches!(error, DispatchError::Internal(_)), "{error:?}");
        let wire = error.into_wire("sandbox/describe");
        assert_eq!(wire.code, CODE_APPLICATION);
        assert!(
            wire.message.contains("sandbox/describe"),
            "{}",
            wire.message
        );

        let Err(bad_params) = parse::<u32>(Value::String("not a number".to_owned())) else {
            panic!("decoding must fail");
        };
        assert!(matches!(bad_params, DispatchError::BadParams(_)));
        assert_eq!(
            bad_params.into_wire("sandbox/describe").code,
            CODE_INVALID_REQUEST
        );
    }
}
