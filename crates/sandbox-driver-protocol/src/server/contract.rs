//! Plugin side of protocol version 3: serves a `contract::ProviderFactory`.
//!
//! `initialize` activates the plugin's own factory with the entry's config and
//! the secrets named by the host, read from this process's environment. Every
//! later call addresses the resulting runtime and its sandboxes by id.

use std::collections::BTreeMap;
use std::env;
use std::sync::Arc;

use sandbox_driver::contract::{
    Activation, ByteStream, Error, ExecControls, MutationOutcome, OutputSink, OutputStream,
    ProviderEntry, ProviderFactory, ProviderRuntime, ProviderSchemas, Sandbox, SecretValues,
    TerminalSize, WorkloadAdmission,
};
use sandbox_driver::{SandboxId, StopLevel};
use serde_json::Value;
use tokio::io::AsyncReadExt;
use tokio::sync::{Mutex as AsyncMutex, OnceCell, OwnedSemaphorePermit, watch};
use tokio::time;
use tokio_util::sync::CancellationToken;
use tokio_util::task::AbortOnDropHandle;

use super::registry::Registry;
use super::{DispatchError, ServerState, parse, to_value};
use crate::channel::{self, Channel, FrameKind};
use crate::contract::stream::{Chunk, chunk_stream};
use crate::contract::wire::{
    self as w, CreateParams, ExecParams, ExecResizeParams, ExecStopParams, FilesGetParams,
    FilesListParams, FilesPutParams, IdParams, InitializeParams, InitializeResult, ListParams,
    PortParams, SandboxInfo,
};
use crate::{TransportLimits, methods as m};

/// An in-flight exec's controls, addressable by the host's exec id.
#[derive(Clone)]
struct ExecHandle {
    term:   CancellationToken,
    kill:   CancellationToken,
    resize: Arc<watch::Sender<TerminalSize>>,
}

pub(crate) struct ContractState {
    schemas:   ProviderSchemas,
    factory:   Arc<dyn ProviderFactory>,
    runtime:   OnceCell<Arc<dyn ProviderRuntime>>,
    sandboxes: Registry<Arc<dyn Sandbox>>,
    execs:     Registry<ExecHandle>,
    closing:   CancellationToken,
}

impl ContractState {
    pub(crate) fn new((schemas, factory): (ProviderSchemas, Arc<dyn ProviderFactory>)) -> Self {
        Self {
            schemas,
            factory,
            runtime: OnceCell::new(),
            sandboxes: Registry::default(),
            execs: Registry::default(),
            closing: CancellationToken::new(),
        }
    }

    fn runtime(&self) -> Result<&Arc<dyn ProviderRuntime>, Error> {
        self.runtime.get().ok_or_else(|| Error::Unavailable {
            message: "the plugin has not been initialized".into(),
            outcome: MutationOutcome::NotStarted,
        })
    }

    /// The connection is ending: every in-flight exec is killed, then the
    /// runtime gets the remaining budget for its own bounded cleanup.
    pub(super) async fn close(&self, limits: &TransportLimits) {
        self.closing.cancel();
        for exec in self.execs.drain() {
            exec.kill.cancel();
        }
        self.sandboxes.drain();
        if let Some(runtime) = self.runtime.get() {
            match time::timeout(limits.shutdown_timeout, runtime.shutdown()).await {
                Ok(Ok(())) => {}
                Ok(Err(error)) => tracing::warn!(error = %error, "plugin runtime cleanup failed"),
                Err(_) => tracing::warn!("plugin runtime cleanup timed out"),
            }
        }
    }
}

fn contract(state: &ServerState) -> Result<&ContractState, Error> {
    state.contract.as_ref().ok_or_else(|| Error::Unsupported {
        capability: format!("protocol version {}", w::PROTOCOL_VERSION),
    })
}

impl From<Error> for DispatchError {
    fn from(error: Error) -> Self {
        Self::Contract(error)
    }
}

pub(super) async fn initialize(state: &ServerState, params: Value) -> Result<Value, DispatchError> {
    let contract = contract(state)?;
    let request: InitializeParams = parse(params)?;
    if request.data_transport.max_frame_bytes != channel::MAX_FRAME_BYTES {
        return Err(Error::InvalidSpec {
            path:    "data_transport.max_frame_bytes".into(),
            message: "must be 65536".into(),
        }
        .into());
    }
    if state.version.get_or_init(|| w::PROTOCOL_VERSION) != &w::PROTOCOL_VERSION {
        return Err(Error::InvalidSpec {
            path:    "protocol_version".into(),
            message: "the connection already negotiated another version".into(),
        }
        .into());
    }
    let _ = state.transport.set(request.data_transport);
    contract
        .runtime
        .get_or_try_init(|| async {
            // Named secrets arrive as this process's environment, exactly as
            // the host resolved them; everything else is launch environment.
            let mut secrets = BTreeMap::new();
            for name in &request.secrets {
                let value = env::var(name).map_err(|_| Error::MissingSecret {
                    entry: request.entry.clone(),
                    name:  name.clone(),
                })?;
                secrets.insert(name.clone(), value);
            }
            let environment = env::vars()
                .filter(|(key, _)| !secrets.contains_key(key))
                .collect();
            let activation = Activation {
                name: request.entry.clone(),
                entry: ProviderEntry {
                    plugin:      contract.schemas.kind.clone(),
                    config:      request.config,
                    secrets:     request.secrets.clone(),
                    path:        None,
                    trust:       None,
                    args:        Vec::new(),
                    env:         BTreeMap::new(),
                    inherit_env: None,
                },
                schemas: contract.schemas.clone(),
                environment,
                secrets: SecretValues::new(secrets),
            };
            contract.factory.activate(activation).await
        })
        .await?;
    to_value(&InitializeResult {
        protocol_version: w::PROTOCOL_VERSION,
    })
}

pub(super) async fn dispatch(
    state: &Arc<ServerState>,
    method: &str,
    params: Value,
    io_permit: Option<Arc<OwnedSemaphorePermit>>,
) -> Result<Value, DispatchError> {
    let contract = contract(state)?;
    let runtime = contract.runtime()?;
    match method {
        w::DESCRIBE => to_value(&runtime.describe().await?),
        w::HEALTH => to_value(&runtime.health().await?),
        w::CREATE => {
            let CreateParams { spec, credentials } = parse(params)?;
            let sandbox = runtime
                .create(WorkloadAdmission {
                    spec,
                    credentials: SecretValues::new(credentials),
                })
                .await?;
            remember(state, contract, sandbox.into())
        }
        w::ATTACH => {
            let IdParams { id } = parse(params)?;
            let sandbox = runtime.attach(&id).await?;
            remember(state, contract, sandbox.into())
        }
        w::LIST => {
            let ListParams { filter } = parse(params)?;
            to_value(&runtime.list(&filter).await?)
        }
        w::DESTROY => {
            let IdParams { id } = parse(params)?;
            runtime.destroy(&id).await?;
            contract.sandboxes.remove(id.as_str());
            to_value(&m::Empty)
        }
        w::STATUS => {
            let IdParams { id } = parse(params)?;
            to_value(&sandbox(contract, &id).await?.status().await?)
        }
        w::START => {
            let IdParams { id } = parse(params)?;
            sandbox(contract, &id).await?.start().await?;
            to_value(&m::Empty)
        }
        w::STOP => {
            let IdParams { id } = parse(params)?;
            sandbox(contract, &id).await?.stop().await?;
            to_value(&m::Empty)
        }
        w::EXEC => exec(state, contract, parse(params)?, io_permit).await,
        w::EXEC_STOP => {
            let ExecStopParams { exec, level } = parse(params)?;
            // An exec that already finished needs no stop.
            if let Some(handle) = contract.execs.get(&exec) {
                match level {
                    StopLevel::Term => handle.term.cancel(),
                    StopLevel::Kill => handle.kill.cancel(),
                }
            }
            to_value(&m::Empty)
        }
        w::EXEC_RESIZE => {
            let ExecResizeParams { exec, size } = parse(params)?;
            if let Some(handle) = contract.execs.get(&exec) {
                handle.resize.send_replace(size);
            }
            to_value(&m::Empty)
        }
        w::FILES_GET => files_get(state, contract, parse(params)?, io_permit).await,
        w::FILES_PUT => files_put(state, contract, parse(params)?, io_permit).await,
        w::FILES_LIST => {
            let FilesListParams {
                sandbox: id,
                path,
                depth,
            } = parse(params)?;
            to_value(
                &sandbox(contract, &id)
                    .await?
                    .files()
                    .list(&path, depth)
                    .await?,
            )
        }
        w::PORTS_EXPOSE => {
            let PortParams {
                sandbox: id,
                port,
                options,
            } = parse(params)?;
            let options = options.ok_or_else(|| Error::InvalidSpec {
                path:    "options".into(),
                message: "expose requires options".into(),
            })?;
            to_value(
                &sandbox(contract, &id)
                    .await?
                    .ports()
                    .expose(port, options)
                    .await?,
            )
        }
        w::PORTS_RELEASE => {
            let PortParams {
                sandbox: id, port, ..
            } = parse(params)?;
            sandbox(contract, &id).await?.ports().release(port).await?;
            to_value(&m::Empty)
        }
        _ => Err(DispatchError::UnknownMethod),
    }
}

fn remember(
    state: &ServerState,
    contract: &ContractState,
    sandbox: Arc<dyn Sandbox>,
) -> Result<Value, DispatchError> {
    let info = SandboxInfo {
        reference:         sandbox.reference(),
        working_directory: sandbox.working_directory().to_path_buf(),
        env:               sandbox.env().clone(),
    };
    contract.sandboxes.insert_bounded(
        info.reference.id.as_str().to_owned(),
        sandbox,
        state.limits.cached_handles,
    );
    to_value(&info)
}

/// A cached handle, or a fresh attach; the runtime decides whether this
/// instance may operate the id.
async fn sandbox(contract: &ContractState, id: &SandboxId) -> Result<Arc<dyn Sandbox>, Error> {
    if let Some(sandbox) = contract.sandboxes.get(id.as_str()) {
        return Ok(sandbox);
    }
    Ok(contract.runtime()?.attach(id).await?.into())
}

async fn open(
    state: &ServerState,
    request: &channel::ChannelRequest,
    permit: Option<Arc<OwnedSemaphorePermit>>,
) -> Result<Channel, Error> {
    state
        .open_channel(request, permit)
        .await
        .map_err(|error| Error::Transport {
            message: error.to_string(),
            outcome: MutationOutcome::NotStarted,
        })
}

fn transport(error: &sandbox_driver::Error) -> Error {
    Error::Transport {
        message: error.to_string(),
        outcome: MutationOutcome::Unknown,
    }
}

/// Unregisters an exec id when its call ends, however it ends.
struct Registered<'a>(&'a ContractState, String);

impl Drop for Registered<'_> {
    fn drop(&mut self) {
        self.0.execs.remove(&self.1);
    }
}

async fn exec(
    state: &ServerState,
    contract: &ContractState,
    params: ExecParams,
    permit: Option<Arc<OwnedSemaphorePermit>>,
) -> Result<Value, DispatchError> {
    let ExecParams {
        sandbox: id,
        exec: exec_id,
        spec,
        stdin,
        channel: request,
    } = params;
    let sandbox = sandbox(contract, &id).await?;
    let (resize, resized) = watch::channel(TerminalSize {
        rows:    24.try_into().expect("non-zero"),
        columns: 80.try_into().expect("non-zero"),
    });
    // Registered before the channel opens, so a stop the host sends once it
    // sees the channel always finds this exec.
    let handle = ExecHandle {
        term:   CancellationToken::new(),
        kill:   contract.closing.child_token(),
        resize: Arc::new(resize),
    };
    if contract
        .execs
        .try_insert(exec_id.clone(), handle.clone())
        .is_err()
    {
        return Err(Error::InvalidSpec {
            path:    "exec".into(),
            message: "exec id is already in use".into(),
        }
        .into());
    }
    let _registered = Registered(contract, exec_id);
    let Channel { mut reader, writer } = open(state, &request, permit).await?;
    let writer = Arc::new(AsyncMutex::new(writer));
    let (input, _input_task) = if stdin {
        let (chunks, input) = chunk_stream();
        let kill = handle.kill.clone();
        let task = AbortOnDropHandle::new(tokio::spawn(async move {
            loop {
                let chunk = match reader.read().await {
                    Ok(Some((FrameKind::Stdin, payload))) => Chunk::Data(payload),
                    Ok(Some((FrameKind::Eof, _))) => Chunk::Done,
                    _ => {
                        // Incomplete or malformed input is not an empty input.
                        kill.cancel();
                        Chunk::Failed("exec input ended before its eof".into())
                    }
                };
                let last = !matches!(chunk, Chunk::Data(_));
                if chunks.send(chunk).await.is_err() || last {
                    return;
                }
            }
        }));
        (Some(Box::pin(input) as ByteStream), Some(task))
    } else {
        (None, None)
    };
    let sink: OutputSink = {
        let writer = Arc::clone(&writer);
        Arc::new(move |stream, chunk| {
            let writer = Arc::clone(&writer);
            Box::pin(async move {
                let kind = match stream {
                    OutputStream::Stdout | OutputStream::Terminal => FrameKind::Stdout,
                    OutputStream::Stderr => FrameKind::Stderr,
                };
                writer
                    .lock()
                    .await
                    .write(kind, &chunk)
                    .await
                    .map_err(|error| transport(&error))
            })
        })
    };
    let outcome = sandbox
        .exec(spec, ExecControls {
            stdin:  input,
            sink:   Some(sink),
            term:   Some(handle.term.clone()),
            kill:   Some(handle.kill.clone()),
            resize: Some(resized),
        })
        .await;
    // Close our side before answering, so no result overtakes its output.
    let finished = writer.lock().await.finish().await;
    let outcome = outcome?;
    finished.map_err(|error| transport(&error))?;
    to_value(&outcome)
}

async fn files_get(
    state: &ServerState,
    contract: &ContractState,
    params: FilesGetParams,
    permit: Option<Arc<OwnedSemaphorePermit>>,
) -> Result<Value, DispatchError> {
    let FilesGetParams {
        sandbox: id,
        path,
        range,
        channel: request,
    } = params;
    let sandbox = sandbox(contract, &id).await?;
    let Channel { mut writer, .. } = open(state, &request, permit).await?;
    let mut content = match sandbox.files().get(&path, range).await {
        Ok(content) => content,
        Err(error) => {
            let _ = writer.finish().await;
            return Err(error.into());
        }
    };
    let mut buffer = vec![0; 64 * 1024];
    loop {
        // A read failure sends no eof: the host must not see a short file.
        let count = content
            .read(&mut buffer)
            .await
            .map_err(|_| Error::Transport {
                message: "reading the file failed".into(),
                outcome: MutationOutcome::Unknown,
            })?;
        if count == 0 {
            break;
        }
        writer
            .write(FrameKind::Stdout, &buffer[..count])
            .await
            .map_err(|error| transport(&error))?;
    }
    writer.finish().await.map_err(|error| transport(&error))?;
    to_value(&m::Empty)
}

async fn files_put(
    state: &ServerState,
    contract: &ContractState,
    params: FilesPutParams,
    permit: Option<Arc<OwnedSemaphorePermit>>,
) -> Result<Value, DispatchError> {
    let FilesPutParams {
        sandbox: id,
        path,
        channel: request,
    } = params;
    let sandbox = sandbox(contract, &id).await?;
    let Channel {
        mut reader,
        mut writer,
    } = open(state, &request, permit).await?;
    let (chunks, content) = chunk_stream();
    let feed = async move {
        loop {
            let chunk = match reader.read().await {
                Ok(Some((FrameKind::Stdin, payload))) => Chunk::Data(payload),
                Ok(Some((FrameKind::Eof, _))) => Chunk::Done,
                _ => Chunk::Failed("the upload ended before its eof".into()),
            };
            let last = !matches!(chunk, Chunk::Data(_));
            if chunks.send(chunk).await.is_err() || last {
                return;
            }
        }
    };
    let ((), written) = tokio::join!(feed, sandbox.files().put(&path, Box::pin(content)));
    // The client may close the channel once its upload is sent; the reply,
    // not this courtesy EOF, reports the outcome.
    let _ = writer.finish().await;
    written?;
    to_value(&m::Empty)
}
