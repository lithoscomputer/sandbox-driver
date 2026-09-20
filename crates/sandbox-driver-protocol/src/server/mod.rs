//! Serves any [`SandboxProvider`] over newline-delimited JSON-RPC.
//!
//! Every request is handled in its own task, so a slow call never blocks
//! its siblings (the interleaving requirement from the design). One
//! writer task owns the control stream; events cross as notifications and
//! every byte stream rides a data channel the plugin opens back to the
//! host ([`crate::channel`]).

use std::collections::HashMap;
use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use async_trait::async_trait;
use sandbox_driver::{
    Error, Event, EventContext, EventObserver, Result, Sandbox, SandboxId, SandboxProvider,
    TransportError,
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

use self::sessions::{ServerPty, ServerStdio};
use crate::channel::{self, Channel, ChannelRequest, DataTransport};
use crate::wire::{CODE_INVALID_REQUEST, CODE_METHOD_NOT_FOUND, Message, WireError};
use crate::{ServerDiagnostics, TransportLimits, control, limits, methods as m};

mod access;
mod exec;
mod fs;
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
