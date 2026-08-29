//! Serves any [`SandboxProvider`] over newline-delimited JSON-RPC.
//!
//! Every request is handled in its own task, so a slow call never blocks
//! its siblings (the interleaving requirement from the design). One
//! writer task owns the output stream; events and exec output cross as
//! notifications.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use sandbox_driver::{
    CheckpointId, Error, EventCallback, ExecControls, OutputSink, Result, Sandbox, SandboxId,
    SandboxProvider, SandboxStatus,
};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader, stdin, stdout};
use tokio::sync::mpsc;
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

    drop(outbound);
    drop(state);
    let _ = writer_task.await;
    Ok(())
}

struct ServerState {
    provider: Arc<dyn SandboxProvider>,
    handles:  Mutex<HashMap<String, Arc<dyn Sandbox>>>,
    execs:    Mutex<HashMap<String, CancellationToken>>,
    outbound: mpsc::Sender<Message>,
}

impl ServerState {
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

    fn event_callback(&self, sandbox_hint: Arc<Mutex<String>>) -> EventCallback {
        let outbound = self.outbound.clone();
        Arc::new(move |event| {
            let sandbox_id = sandbox_hint.lock().expect("hint lock").clone();
            let notification = Message::notification(
                m::HOST_EVENT,
                serde_json::to_value(m::HostEventNotification { sandbox_id, event })
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
            // events during create carry an empty id, everything after
            // routes correctly.
            let hint = Arc::new(Mutex::new(String::new()));
            let callback = state.event_callback(Arc::clone(&hint));
            let handle = state.provider.create(&request.spec, Some(callback)).await?;
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
            let callback = state.event_callback(Arc::new(Mutex::new(request.sandbox_id.clone())));
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
        m::SANDBOX_FORK => {
            let request: m::ForkParams = parse(params)?;
            let handle = state.sandbox(&request.sandbox_id).await?;
            let forked = handle.fork(&request.options).await?;
            state.remember(&forked);
            let status = forked.describe().await?;
            to_value(&handle_info(&forked, status))
        }
        m::SANDBOX_CHECKPOINT => {
            let request: m::CheckpointParams = parse(params)?;
            let handle = state.sandbox(&request.sandbox_id).await?;
            let checkpoint = handle.checkpoint(&request.options).await?;
            to_value(&m::CheckpointResult {
                checkpoint_id: checkpoint.as_str().to_owned(),
            })
        }
        m::SANDBOX_RESTORE_CHECKPOINT => {
            let request: m::RestoreCheckpointParams = parse(params)?;
            let handle = state.sandbox(&request.sandbox_id).await?;
            let checkpoint = CheckpointId::try_new(&request.checkpoint_id)
                .map_err(|error| Error::invalid_spec("checkpoint_id", error.to_string()))?;
            handle.restore_checkpoint(&checkpoint).await?;
            to_value(&m::Empty)
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
            let snapshot = state
                .sandbox(&request.sandbox_id)
                .await?
                .snapshot(&request.options)
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
        m::FS_READ => {
            let request: m::FsPathParams = parse(params)?;
            let content = state
                .sandbox(&request.sandbox_id)
                .await?
                .fs()
                .read(&request.path)
                .await?;
            to_value(&m::FsReadResult {
                content_b64: encode_bytes(&content),
            })
        }
        m::FS_WRITE => {
            let request: m::FsWriteParams = parse(params)?;
            let content = decode_bytes(&request.content_b64)?;
            state
                .sandbox(&request.sandbox_id)
                .await?
                .fs()
                .write(&request.path, &content)
                .await?;
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
        _ => Err(DispatchError::UnknownMethod),
    }
}
