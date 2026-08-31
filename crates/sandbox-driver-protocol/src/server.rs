//! Serves any [`SandboxProvider`] over newline-delimited JSON-RPC.
//!
//! Every request is handled in its own task, so a slow call never blocks
//! its siblings (the interleaving requirement from the design). One
//! writer task owns the output stream; events and exec output cross as
//! notifications.

use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use sandbox_driver::{
    Capability, Error, EventCallback, ExecControls, LogSink, OutputSink, Result, Sandbox,
    SandboxId, SandboxProvider, SandboxSpec, SandboxStatus, SnapshotId, StderrTail,
    StdioProcessHandle, VolumeId,
};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;
use tokio::io::{
    AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, stdin, stdout,
};
use tokio::sync::{Mutex as AsyncMutex, mpsc};
use tokio_util::sync::CancellationToken;

use crate::methods as m;
use crate::wire::{
    CODE_INVALID_REQUEST, CODE_METHOD_NOT_FOUND, Message, WireError, decode_bytes, encode_bytes,
};

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
/// the conformance tests drive it.
pub async fn serve(
    provider: Arc<dyn SandboxProvider>,
    reader: impl AsyncRead + Unpin + Send + 'static,
    writer: impl AsyncWrite + Unpin + Send + 'static,
) -> Result<()> {
    let (outbound, mut outbound_rx) = mpsc::channel::<Message>(256);
    let writer_task = tokio::spawn(async move {
        let mut writer = writer;
        while let Some(message) = outbound_rx.recv().await {
            let Ok(mut line) = serde_json::to_string(&message) else {
                continue;
            };
            line.push('\n');
            if writer.write_all(line.as_bytes()).await.is_err() {
                break;
            }
        }
        let _ = writer.shutdown().await;
    });

    let state = Arc::new(ServerState {
        provider,
        handles: Mutex::new(HashMap::new()),
        execs: Mutex::new(HashMap::new()),
        stdios: Mutex::new(HashMap::new()),
        ptys: Mutex::new(HashMap::new()),
        streams: Mutex::new(HashMap::new()),
        outbound: outbound.clone(),
    });

    let shutdown = CancellationToken::new();
    let mut lines = BufReader::new(reader).lines();
    loop {
        let line = tokio::select! {
            line = lines.next_line() => line,
            () = shutdown.cancelled() => break,
        };
        let Ok(Some(line)) = line else { break };
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
            // v1 has no host→plugin notifications; ignore.
            continue;
        };
        if method == m::SHUTDOWN {
            let _ = outbound.send(Message::response(id, Value::Null)).await;
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
            let _ = state.outbound.send(reply).await;
        });
    }

    state.close_sessions().await;
    drop(outbound);
    drop(state);
    let _ = writer_task.await;
    Ok(())
}

struct ServerState {
    provider: Arc<dyn SandboxProvider>,
    handles:  Mutex<HashMap<String, Arc<dyn Sandbox>>>,
    execs:    Mutex<HashMap<String, CancellationToken>>,
    stdios:   Mutex<HashMap<String, Arc<ServerStdio>>>,
    ptys:     Mutex<HashMap<String, Arc<dyn sandbox_driver::PtySession>>>,
    streams:  Mutex<HashMap<String, CancellationToken>>,
    outbound: mpsc::Sender<Message>,
}

struct ServerStdio {
    stdin:       AsyncMutex<Pin<Box<dyn AsyncWrite + Send>>>,
    stdout:      AsyncMutex<Pin<Box<dyn AsyncRead + Send>>>,
    stderr_tail: StderrTail,
    handle:      Arc<dyn StdioProcessHandle>,
    stdout_done: AtomicBool,
    waited:      AtomicBool,
}

impl ServerState {
    async fn close_sessions(&self) {
        let execs = self
            .execs
            .lock()
            .expect("execs lock")
            .drain()
            .map(|(_, token)| token)
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
            .map(|(_, process)| process)
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
            let _ = session.close().await;
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

    fn event_callback(
        &self,
        sandbox_hint: Arc<Mutex<String>>,
        operation_id: Option<String>,
    ) -> EventCallback {
        let outbound = self.outbound.clone();
        Arc::new(move |event| {
            let sandbox_id = sandbox_hint.lock().expect("hint lock").clone();
            let notification = Message::notification(
                m::HOST_EVENT,
                serde_json::to_value(m::HostEventNotification {
                    sandbox_id,
                    event,
                    operation_id: operation_id.clone(),
                })
                .unwrap_or(Value::Null),
            );
            // Best-effort: an overflowing notification queue drops the
            // event rather than blocking the provider.
            let _ = outbound.try_send(notification);
        })
    }
}

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

fn forget_stdio_if_finished(state: &ServerState, id: &str, process: &ServerStdio) {
    if process.stdout_done.load(Ordering::SeqCst) && process.waited.load(Ordering::SeqCst) {
        state.stdios.lock().expect("stdios lock").remove(id);
    }
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

fn log_sink(state: &ServerState, stream_id: &str) -> LogSink {
    let outbound = state.outbound.clone();
    let stream_id = stream_id.to_owned();
    Arc::new(move |chunk| {
        let outbound = outbound.clone();
        let stream_id = stream_id.clone();
        Box::pin(async move {
            let notification = Message::notification(
                m::LOG_OUTPUT,
                serde_json::to_value(m::LogOutputNotification {
                    stream_id,
                    data_b64: encode_bytes(&chunk),
                })
                .unwrap_or(Value::Null),
            );
            outbound
                .send(notification)
                .await
                .map_err(|_| Error::invalid_spec("transport", "notification channel closed"))
        })
    })
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

async fn dispatch(
    state: &Arc<ServerState>,
    method: &str,
    params: Value,
) -> Result<Value, DispatchError> {
    match method {
        m::INITIALIZE => {
            let request: m::InitializeParams = parse(params)?;
            if request.protocol_version != m::PROTOCOL_VERSION {
                return Err(DispatchError::App(Error::invalid_spec(
                    "protocol_version",
                    format!(
                        "plugin speaks protocol version {} but the host asked for {}",
                        m::PROTOCOL_VERSION,
                        request.protocol_version
                    ),
                )));
            }
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
            // The id exists only after create: the hint is bound late, so
            // events during create carry an empty id (and the caller's
            // operation_id, when one was sent, for correlation);
            // everything after routes correctly.
            let hint = Arc::new(Mutex::new(String::new()));
            let callback = state.event_callback(Arc::clone(&hint), request.operation_id.clone());
            let spec = SandboxSpec::try_from(request.spec)?;
            let handle = state.provider.create(&spec, Some(callback)).await?;
            handle
                .id()
                .as_str()
                .clone_into(&mut hint.lock().expect("hint lock"));
            state.remember(&handle);
            let status = handle.describe().await?;
            to_value(&handle_info(&handle, status))
        }
        m::SANDBOX_ATTACH => {
            let request: m::AttachParams = parse(params)?;
            let sandbox_id = SandboxId::try_new(&request.sandbox_id)
                .map_err(|error| Error::invalid_spec("sandbox_id", error.to_string()))?;
            let callback =
                state.event_callback(Arc::new(Mutex::new(request.sandbox_id.clone())), None);
            let handle = state.provider.attach(&sandbox_id, Some(callback)).await?;
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
        m::SANDBOX_START
        | m::SANDBOX_STOP
        | m::SANDBOX_DELETE
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
                m::SANDBOX_DELETE => handle.delete().await?,
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
            let callback =
                state.event_callback(Arc::new(Mutex::new(request.sandbox_id.clone())), None);
            let handle = state.provider.undelete(&sandbox_id, Some(callback)).await?;
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
        m::EXEC_RUN => {
            let request: m::ExecRunParams = parse(params)?;
            let handle = state.sandbox(&request.sandbox_id).await?;
            let spec = request.spec.into_spec()?;
            let result = handle.exec().run(&spec).await?;
            to_value(&m::ExecResultDto::from_result(&result))
        }
        m::EXEC_STREAM => {
            let request: m::ExecStreamParams = parse(params)?;
            let handle = state.sandbox(&request.sandbox_id).await?;
            let spec = request.spec.into_spec()?;
            let cancel = CancellationToken::new();
            state
                .execs
                .lock()
                .expect("execs lock")
                .insert(request.exec_id.clone(), cancel.clone());

            let outbound = state.outbound.clone();
            let exec_id = request.exec_id.clone();
            let sink: OutputSink = Arc::new(move |stream, chunk| {
                let outbound = outbound.clone();
                let exec_id = exec_id.clone();
                Box::pin(async move {
                    let notification = Message::notification(
                        m::EXEC_OUTPUT,
                        serde_json::to_value(m::ExecOutputNotification {
                            exec_id,
                            stream,
                            data_b64: encode_bytes(&chunk),
                        })
                        .unwrap_or(Value::Null),
                    );
                    outbound.send(notification).await.map_err(|_| {
                        Error::invalid_spec("transport", "notification channel closed")
                    })?;
                    Ok(())
                })
            });

            let controls = ExecControls {
                cancel:                Some(cancel),
                sink:                  Some(sink),
                retained_output_limit: request.retained_output_limit,
            };
            let outcome = handle.exec().run_streaming(&spec, controls).await;
            state
                .execs
                .lock()
                .expect("execs lock")
                .remove(&request.exec_id);
            let streaming = outcome?;
            to_value(&m::ExecStreamResult {
                result:            m::ExecResultDto::from_result(&streaming.result),
                streams_separated: streaming.streams_separated,
                live_streaming:    streaming.live_streaming,
                stdout_capture:    streaming.stdout_capture,
                stderr_capture:    streaming.stderr_capture,
            })
        }
        m::EXEC_CANCEL => {
            let request: m::ExecCancelParams = parse(params)?;
            if let Some(token) = state
                .execs
                .lock()
                .expect("execs lock")
                .get(&request.exec_id)
            {
                token.cancel();
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
            let process = Arc::new(ServerStdio {
                stdin:       AsyncMutex::new(process.stdin),
                stdout:      AsyncMutex::new(process.stdout),
                stderr_tail: process.stderr_tail,
                handle:      Arc::from(process.handle),
                stdout_done: AtomicBool::new(false),
                waited:      AtomicBool::new(false),
            });
            let inserted = {
                let mut stdios = state.stdios.lock().expect("stdios lock");
                match stdios.entry(request.process_id.clone()) {
                    Entry::Vacant(entry) => {
                        entry.insert(Arc::clone(&process));
                        true
                    }
                    Entry::Occupied(_) => false,
                }
            };
            if !inserted {
                process.handle.terminate().await;
                return Err(Error::invalid_spec("process_id", "duplicate stdio process id").into());
            }
            to_value(&m::Empty)
        }
        m::EXEC_STDIO_INPUT => {
            let request: m::StdioInputParams = parse(params)?;
            let process = stdio(state, &request.process_id)?;
            let data = decode_bytes(&request.data_b64)?;
            process
                .stdin
                .lock()
                .await
                .write_all(&data)
                .await
                .map_err(|error| Error::io("writing remote process stdin", error))?;
            to_value(&m::Empty)
        }
        m::EXEC_STDIO_CLOSE_INPUT => {
            let request: m::StdioIdParams = parse(params)?;
            let process = stdio(state, &request.process_id)?;
            process
                .stdin
                .lock()
                .await
                .shutdown()
                .await
                .map_err(|error| Error::io("closing remote process stdin", error))?;
            to_value(&m::Empty)
        }
        m::EXEC_STDIO_OUTPUT => {
            let request: m::StdioIdParams = parse(params)?;
            let process = stdio(state, &request.process_id)?;
            let mut chunk = vec![0; 32 * 1024];
            let read = process
                .stdout
                .lock()
                .await
                .read(&mut chunk)
                .await
                .map_err(|error| Error::io("reading remote process stdout", error))?;
            chunk.truncate(read);
            if read == 0 {
                process.stdout_done.store(true, Ordering::SeqCst);
                forget_stdio_if_finished(state, &request.process_id, &process);
            }
            to_value(&m::StdioOutputResult {
                data_b64: (read != 0).then(|| encode_bytes(&chunk)),
            })
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
            process.waited.store(true, Ordering::SeqCst);
            forget_stdio_if_finished(state, &request.process_id, &process);
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
                match ptys.entry(request.pty_id) {
                    Entry::Vacant(entry) => {
                        entry.insert(Arc::clone(&pty));
                        true
                    }
                    Entry::Occupied(_) => false,
                }
            };
            if !inserted {
                let _ = pty.close().await;
                return Err(Error::invalid_spec("pty_id", "duplicate PTY id").into());
            }
            to_value(&m::Empty)
        }
        m::PTY_INPUT => {
            let request: m::PtyInputParams = parse(params)?;
            pty(state, &request.pty_id)?
                .write_input(&decode_bytes(&request.data_b64)?)
                .await?;
            to_value(&m::Empty)
        }
        m::PTY_OUTPUT => {
            let request: m::PtyIdParams = parse(params)?;
            let chunk = pty(state, &request.pty_id)?.read_output().await?;
            to_value(&m::PtyOutputResult {
                data_b64: chunk.as_deref().map(encode_bytes),
            })
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
            follow_logs(
                state,
                &request.stream_id,
                logs.follow(request.source, log_sink(state, &request.stream_id)),
            )
            .await?;
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
            let content = if request.offset.is_some() || request.length.is_some() {
                handle
                    .fs()
                    .read_range(&request.path, request.offset.unwrap_or(0), request.length)
                    .await?
            } else {
                handle.fs().read(&request.path).await?
            };
            to_value(&m::FsReadResult {
                content_b64: encode_bytes(&content),
            })
        }
        m::FS_WRITE => {
            let request: m::FsWriteParams = parse(params)?;
            let content = decode_bytes(&request.content_b64)?;
            let handle = state.sandbox(&request.sandbox_id).await?;
            if request.append {
                handle.fs().write_append(&request.path, &content).await?;
            } else {
                handle.fs().write(&request.path, &content).await?;
            }
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
            let spec = request.spec.into();
            let service =
                state
                    .provider
                    .snapshots()
                    .ok_or(DispatchError::App(Error::unsupported(
                        Capability::Snapshots,
                    )))?;
            let id = service.create(&spec).await?;
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
            follow_logs(
                state,
                &request.stream_id,
                service.build_logs(&id, request.follow, log_sink(state, &request.stream_id)),
            )
            .await?;
            to_value(&m::Empty)
        }
        m::SNAPSHOT_DELETE | m::SNAPSHOT_ACTIVATE | m::SNAPSHOT_DEACTIVATE => {
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
            match method {
                m::SNAPSHOT_ACTIVATE => service.activate(&id).await?,
                m::SNAPSHOT_DEACTIVATE => service.deactivate(&id).await?,
                _ => service.delete(&id).await?,
            }
            to_value(&m::Empty)
        }
        m::PROVIDER_HEALTH => {
            let health = state.provider.health().await?;
            to_value(&m::HealthResult { health })
        }
        m::VOLUME_CREATE => {
            let request: m::VolumeCreateParams = parse(params)?;
            let service = state
                .provider
                .volumes()
                .ok_or(DispatchError::App(Error::unsupported(Capability::Volumes)))?;
            let id = service.create(&request.spec).await?;
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
            let service = state
                .provider
                .volumes()
                .ok_or(DispatchError::App(Error::unsupported(Capability::Volumes)))?;
            let id = VolumeId::try_new(&request.volume_id)
                .map_err(|error| Error::invalid_spec("volume_id", error.to_string()))?;
            service.delete(&id).await?;
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
