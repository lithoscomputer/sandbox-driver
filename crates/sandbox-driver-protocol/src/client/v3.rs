//! Host side of protocol version 3: a configured plugin child adapted to
//! `sandbox_driver::contract::ProviderRuntime`.
//!
//! Each launch is a *generation*. Handles keep the generation that issued
//! them and fail with `Stale` once it ends. A runtime call after a crash
//! launches a new generation, which must report the same schemas and
//! namespace; the call that was in flight when the old one died is never
//! sent again.

use std::collections::BTreeMap;
use std::future;
use std::num::NonZeroU16;
use std::path::Path;
use std::process::{Command as StdCommand, Stdio};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use sandbox_driver::contract::{
    ByteStream, Descriptor, Error, ExecControls, ExecOutcome, ExecSpec, Expose, Exposure,
    FileEntry, FileRange, Files, Health, LabelFilter, MutationOutcome, OutputStream, Ports,
    ProviderName, ProviderRuntime, ProviderSchemas, Sandbox, SandboxRef, SandboxSummary, Status,
    TerminalSize, WorkloadAdmission,
};
use sandbox_driver::{SandboxId, StopLevel, TransportError};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;
use tokio::io::AsyncReadExt;
use tokio::process::{Child, Command};
use tokio::sync::{Mutex as AsyncMutex, OwnedSemaphorePermit, oneshot, watch};
use tokio::time;
use tokio_util::sync::CancellationToken;
use tokio_util::task::AbortOnDropHandle;

use super::{Client, Failure};
use crate::channel::{Channel, ChannelListener, FrameKind, TrustedPeer};
use crate::metadata::DiscoveredPlugin;
use crate::v3::stream::{Chunk, chunk_stream};
use crate::v3::wire::{
    self as w, CreateParams, ExecParams, ExecResizeParams, ExecStopParams, FilesGetParams,
    FilesListParams, FilesPutParams, IdParams, InitializeParams, InitializeResult, ListParams,
    PortParams, SandboxInfo, from_failure,
};
use crate::{TransportLimits, methods as m};

/// Covers process start, the handshake and the plugin's own activation.
const INITIALIZE_TIMEOUT: Duration = Duration::from_secs(30);

/// Everything needed to start the same configured plugin again.
pub(crate) struct Launch {
    /// Re-verified before every start, so a restart never runs other bytes.
    pub plugin:      DiscoveredPlugin,
    pub entry:       ProviderName,
    pub args:        Vec<String>,
    /// The complete child environment, secrets included.
    pub environment: BTreeMap<String, String>,
    pub config:      BTreeMap<String, Value>,
    pub secrets:     Vec<String>,
    pub schemas:     ProviderSchemas,
    pub limits:      TransportLimits,
}

/// One running plugin process and its connection.
pub(crate) struct Generation {
    client:     Arc<Client>,
    descriptor: Descriptor,
    process:    Supervised,
}

/// A plugin child reaped the moment it exits. An unreaped child is a zombie
/// that still answers `kill -0`, so its own workloads' owner checks would
/// keep treating a dead plugin as alive. Dropping it kills the child.
struct Supervised {
    kill:        CancellationToken,
    exited:      watch::Receiver<bool>,
    _supervisor: AbortOnDropHandle<()>,
}

impl Supervised {
    fn new(mut child: Child) -> Self {
        let kill = CancellationToken::new();
        let (reaped, exited) = watch::channel(false);
        let supervisor = tokio::spawn({
            let kill = kill.clone();
            async move {
                tokio::select! {
                    _ = child.wait() => {}
                    () = kill.cancelled() => {
                        let _ = child.start_kill();
                        let _ = child.wait().await;
                    }
                }
                let _ = reaped.send(true);
            }
        });
        Self {
            kill,
            exited,
            _supervisor: AbortOnDropHandle::new(supervisor),
        }
    }

    async fn reaped(&self) -> bool {
        self.exited.clone().wait_for(|exited| *exited).await.is_ok()
    }
}

impl Generation {
    async fn start(launch: &Launch) -> Result<Arc<Self>, Error> {
        launch.plugin.verify_unchanged(&launch.entry).await?;
        let mut command = StdCommand::new(launch.plugin.path());
        command
            .args(&launch.args)
            .env_clear()
            .envs(&launch.environment)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped());
        let mut command = Command::from(command);
        command.kill_on_drop(true);
        let mut child = command
            .spawn()
            .map_err(|_| not_started(&launch.entry, "the plugin executable could not start"))?;
        let stdin = child.stdin.take().expect("stdin was piped");
        let stdout = child.stdout.take().expect("stdout was piped");
        let pid = child
            .id()
            .ok_or_else(|| not_started(&launch.entry, "the plugin exited during startup"))?;
        let process = Supervised::new(child);
        let listener =
            ChannelListener::bind_with_limits(launch.limits.clone(), TrustedPeer::Process(pid))
                .map_err(|error| from_failure(Failure::Local(error)))?;
        let transport = listener.transport();
        let client = Client::start(stdout, stdin, listener, launch.limits.clone());
        let started = async {
            let initialized = client
                .request(m::INITIALIZE, &InitializeParams {
                    protocol_version: w::PROTOCOL_VERSION,
                    data_transport:   transport,
                    entry:            launch.entry.clone(),
                    config:           launch.config.clone(),
                    secrets:          launch.secrets.clone(),
                })
                .await
                .map_err(|failure| initialize_error(&launch.entry, failure))?;
            let initialized: InitializeResult = decode(m::INITIALIZE, initialized)?;
            if initialized.protocol_version != w::PROTOCOL_VERSION {
                return Err(not_started(
                    &launch.entry,
                    &format!(
                        "the plugin answered protocol version {}, not {}",
                        initialized.protocol_version,
                        w::PROTOCOL_VERSION
                    ),
                ));
            }
            let descriptor = client
                .request(w::DESCRIBE, &m::Empty)
                .await
                .map_err(from_failure)?;
            let descriptor: Descriptor = decode(w::DESCRIBE, descriptor)?;
            if descriptor.schemas != launch.schemas {
                return Err(Error::InvalidConfig {
                    entry:   launch.entry.clone(),
                    path:    "schemas".into(),
                    message: "the running plugin's metadata disagrees with discovery".into(),
                });
            }
            Ok(descriptor)
        };
        let generation = |descriptor| {
            Arc::new(Self {
                client: Arc::clone(&client),
                descriptor,
                process,
            })
        };
        match time::timeout(INITIALIZE_TIMEOUT, started).await {
            Ok(Ok(descriptor)) => Ok(generation(masked(descriptor))),
            Ok(Err(error)) => {
                // Nothing was admitted; the child is killed when dropped.
                Err(error)
            }
            Err(_) => Err(not_started(
                &launch.entry,
                "the plugin did not finish initializing in time",
            )),
        }
    }

    fn is_closed(&self) -> bool {
        self.client.closed.load(Ordering::SeqCst)
    }

    /// A handle from a generation that has ended can never be used again.
    fn live(&self) -> Result<(), Error> {
        if self.is_closed() {
            Err(Error::Stale {
                outcome: MutationOutcome::NotStarted,
            })
        } else {
            Ok(())
        }
    }

    async fn call<P: Serialize, R: DeserializeOwned>(
        &self,
        method: &str,
        params: &P,
    ) -> Result<R, Error> {
        self.live()?;
        let value = self
            .client
            .request(method, params)
            .await
            .map_err(from_failure)?;
        decode(method, value)
    }

    /// Asks the plugin to end and reaps it; kills it when the shared deadline
    /// passes. A failure is never evidence that its workloads stopped.
    async fn shutdown(&self) -> Result<(), Error> {
        self.client.shutdown_requested.store(true, Ordering::SeqCst);
        let outcome = time::timeout(self.client.limits.shutdown_timeout, async {
            if !self.is_closed() {
                self.client
                    .request(m::SHUTDOWN, &m::Empty)
                    .await
                    .map_err(from_failure)?;
            }
            if self.process.reaped().await {
                Ok(())
            } else {
                Err(Error::Transport {
                    message: "the plugin process could not be reaped".into(),
                    outcome: MutationOutcome::Unknown,
                })
            }
        })
        .await
        .unwrap_or_else(|_| {
            Err(Error::Transport {
                message: "the plugin did not shut down in time".into(),
                outcome: MutationOutcome::Unknown,
            })
        });
        if outcome.is_err() {
            self.process.kill.cancel();
        }
        outcome
    }

    fn kill(&self) {
        self.process.kill.cancel();
    }

    fn wrap(self: &Arc<Self>, info: SandboxInfo) -> Box<dyn Sandbox> {
        let id = info.reference.id.clone();
        Box::new(PluginSandbox {
            files: PluginFiles {
                generation: Arc::clone(self),
                id:         id.clone(),
            },
            ports: PluginPorts {
                generation: Arc::clone(self),
                id,
            },
            generation: Arc::clone(self),
            info,
        })
    }
}

/// The optional capability groups this adapter does not yet carry are
/// reported as absent, matching the handles' `None` accessors.
fn masked(mut descriptor: Descriptor) -> Descriptor {
    descriptor.capabilities.lifecycle.clear();
    descriptor.capabilities.endpoints.clear();
    descriptor.capabilities.containers = false;
    descriptor
}

/// A configured plugin entry: one live generation at a time.
pub(crate) struct PluginRuntime {
    launch:    Launch,
    current:   AsyncMutex<Option<Arc<Generation>>>,
    /// The first generation's namespace; a restart must report the same.
    namespace: Mutex<Option<Descriptor>>,
    closed:    CancellationToken,
}

impl PluginRuntime {
    pub(crate) async fn start(launch: Launch) -> Result<Arc<Self>, Error> {
        let runtime = Arc::new(Self {
            launch,
            current: AsyncMutex::new(None),
            namespace: Mutex::new(None),
            closed: CancellationToken::new(),
        });
        runtime.generation().await?;
        Ok(runtime)
    }

    /// The live generation, starting a new one after a crash. Only the
    /// transport is restored: no earlier call is replayed and no sandbox is
    /// restarted.
    async fn generation(&self) -> Result<Arc<Generation>, Error> {
        let stale = || Error::Stale {
            outcome: MutationOutcome::NotStarted,
        };
        if self.closed.is_cancelled() {
            return Err(stale());
        }
        let mut current = self.current.lock().await;
        if let Some(generation) = current.as_ref() {
            if !generation.is_closed() {
                return Ok(Arc::clone(generation));
            }
            generation.kill();
        }
        if self.closed.is_cancelled() {
            return Err(stale());
        }
        let generation = Generation::start(&self.launch).await?;
        let mut first = self.namespace.lock().expect("namespace lock");
        match first.as_ref() {
            Some(original) if original.namespace != generation.descriptor.namespace => {
                generation.kill();
                return Err(Error::NamespaceMismatch {
                    expected: original.namespace.id.clone(),
                    actual:   generation.descriptor.namespace.id.clone(),
                });
            }
            Some(_) => {}
            None => *first = Some(generation.descriptor.clone()),
        }
        drop(first);
        *current = Some(Arc::clone(&generation));
        Ok(generation)
    }

    async fn call<P: Serialize, R: DeserializeOwned>(
        &self,
        method: &str,
        params: &P,
    ) -> Result<R, Error> {
        self.generation().await?.call(method, params).await
    }
}

#[async_trait]
impl ProviderRuntime for PluginRuntime {
    async fn describe(&self) -> Result<Descriptor, Error> {
        Ok(self.generation().await?.descriptor.clone())
    }

    async fn health(&self) -> Result<Health, Error> {
        self.call(w::HEALTH, &m::Empty).await
    }

    async fn create(&self, admission: WorkloadAdmission) -> Result<Box<dyn Sandbox>, Error> {
        let generation = self.generation().await?;
        let info: SandboxInfo = generation
            .call(w::CREATE, &CreateParams {
                spec:        admission.spec,
                credentials: admission.credentials.values().clone(),
            })
            .await?;
        Ok(generation.wrap(info))
    }

    async fn attach(&self, id: &SandboxId) -> Result<Box<dyn Sandbox>, Error> {
        let generation = self.generation().await?;
        let info: SandboxInfo = generation
            .call(w::ATTACH, &IdParams { id: id.clone() })
            .await?;
        Ok(generation.wrap(info))
    }

    async fn list(&self, filter: &LabelFilter) -> Result<Vec<SandboxSummary>, Error> {
        self.call(w::LIST, &ListParams {
            filter: filter.clone(),
        })
        .await
    }

    async fn destroy(&self, id: &SandboxId) -> Result<(), Error> {
        let _: m::Empty = self.call(w::DESTROY, &IdParams { id: id.clone() }).await?;
        Ok(())
    }

    async fn shutdown(&self) -> Result<(), Error> {
        self.closed.cancel();
        let generation = self.current.lock().await.take();
        match generation {
            Some(generation) => generation.shutdown().await,
            None => Ok(()),
        }
    }
}

struct PluginSandbox {
    generation: Arc<Generation>,
    info:       SandboxInfo,
    files:      PluginFiles,
    ports:      PluginPorts,
}

impl PluginSandbox {
    fn id(&self) -> IdParams {
        IdParams {
            id: self.info.reference.id.clone(),
        }
    }
}

#[async_trait]
impl Sandbox for PluginSandbox {
    fn reference(&self) -> SandboxRef {
        self.info.reference.clone()
    }
    fn working_directory(&self) -> &Path {
        &self.info.working_directory
    }
    fn env(&self) -> &BTreeMap<String, String> {
        &self.info.env
    }
    async fn status(&self) -> Result<Status, Error> {
        self.generation.call(w::STATUS, &self.id()).await
    }
    async fn start(&self) -> Result<(), Error> {
        let _: m::Empty = self.generation.call(w::START, &self.id()).await?;
        Ok(())
    }
    async fn stop(&self) -> Result<(), Error> {
        let _: m::Empty = self.generation.call(w::STOP, &self.id()).await?;
        Ok(())
    }
    async fn exec(&self, spec: ExecSpec, controls: ExecControls) -> Result<ExecOutcome, Error> {
        self.generation.live()?;
        exec(
            &self.generation.client,
            self.info.reference.id.clone(),
            spec,
            controls,
        )
        .await
    }
    fn files(&self) -> &dyn Files {
        &self.files
    }
    fn ports(&self) -> &dyn Ports {
        &self.ports
    }
}

/// What the output pump learned, beyond transport failures.
struct Pumped {
    sink_error: Option<Error>,
}

async fn exec(
    client: &Arc<Client>,
    sandbox: SandboxId,
    spec: ExecSpec,
    controls: ExecControls,
) -> Result<ExecOutcome, Error> {
    let (channel, receiver) = client
        .listener
        .expect()
        .map_err(Failure::Local)
        .map_err(from_failure)?;
    let exec_id = format!(
        "exec-{}",
        client.next_operation.fetch_add(1, Ordering::Relaxed)
    );
    let ExecControls {
        stdin,
        sink,
        term,
        kill,
        resize,
    } = controls;
    let params = ExecParams {
        sandbox,
        exec: exec_id.clone(),
        spec,
        stdin: stdin.is_some(),
        channel,
    };
    // Dropping this future before the plugin answers requests a kill; the
    // cleanup is owned by the connection and bounded by its deadline.
    let mut guard = ExecGuard {
        client:  Arc::clone(client),
        exec_id: exec_id.clone(),
        permit:  Some(receiver.io_permit()),
    };
    let kill = kill.unwrap_or_default();
    let pump = {
        let kill = kill.clone();
        let exec_id = exec_id.clone();
        move |Channel {
                  mut reader,
                  mut writer,
              }: Channel| async move {
            let _controls = AbortOnDropHandle::new(tokio::spawn(forward_controls(
                Arc::clone(client),
                exec_id,
                term,
                kill.clone(),
                resize,
            )));
            let _stdin = stdin.map(|mut input| {
                AbortOnDropHandle::new(tokio::spawn(async move {
                    let mut buffer = vec![0; 64 * 1024];
                    loop {
                        match input.read(&mut buffer).await {
                            Ok(0) => break,
                            Ok(count) => {
                                if writer
                                    .write(FrameKind::Stdin, &buffer[..count])
                                    .await
                                    .is_err()
                                {
                                    // The command stopped reading its input.
                                    return;
                                }
                            }
                            // An unreadable input is not a complete one: no eof.
                            Err(_) => return,
                        }
                    }
                    let _ = writer.finish().await;
                }))
            });
            let mut pumped = Pumped { sink_error: None };
            while let Some((kind, payload)) = reader.read().await? {
                let stream = match kind {
                    FrameKind::Stdout => OutputStream::Stdout,
                    FrameKind::Stderr => OutputStream::Stderr,
                    FrameKind::Eof => break,
                    _ => {
                        return Err(Failure::Local(sandbox_driver::Error::Transport(
                            TransportError::new("unexpected frame on exec output"),
                        )));
                    }
                };
                if pumped.sink_error.is_some() || payload.is_empty() {
                    continue;
                }
                if let Some(sink) = &sink {
                    let delivered =
                        time::timeout(client.limits.output_progress_timeout, sink(stream, payload))
                            .await
                            .unwrap_or_else(|_| {
                                Err(Error::Transport {
                                    message: "output sink made no progress".into(),
                                    outcome: MutationOutcome::Unknown,
                                })
                            });
                    if let Err(error) = delivered {
                        kill.cancel();
                        pumped.sink_error = Some(error);
                    }
                }
            }
            Ok(pumped)
        }
    };
    let call = async {
        let value = client.request(w::EXEC, &params).await?;
        serde_json::from_value::<ExecOutcome>(value).map_err(|_| {
            Failure::Local(sandbox_driver::Error::Transport(TransportError::new(
                "the plugin returned an invalid exec outcome",
            )))
        })
    };
    let result = client
        .call_with_channel(w::EXEC, call, receiver, pump)
        .await;
    guard.permit = None;
    let (outcome, pumped) = result.map_err(from_failure)?;
    match pumped.sink_error {
        Some(error) => Err(error),
        None => Ok(outcome),
    }
}

struct ExecGuard {
    client:  Arc<Client>,
    exec_id: String,
    /// Present until the plugin has answered.
    permit:  Option<Arc<OwnedSemaphorePermit>>,
}

impl Drop for ExecGuard {
    fn drop(&mut self) {
        if let Some(permit) = self.permit.take() {
            let client = Arc::clone(&self.client);
            let exec_id = self.exec_id.clone();
            self.client.own_cleanup(permit, async move {
                client
                    .cleanup_call(w::EXEC_STOP, &ExecStopParams {
                        exec:  exec_id,
                        level: StopLevel::Kill,
                    })
                    .await
            });
        }
    }
}

/// Sends `term`, then `kill`, as each token fires, and the latest terminal
/// size on change. Stops are reserved requests, answered while output flows.
async fn forward_controls(
    client: Arc<Client>,
    exec_id: String,
    term: Option<CancellationToken>,
    kill: CancellationToken,
    resize: Option<watch::Receiver<TerminalSize>>,
) {
    let stop = |level| {
        let client = Arc::clone(&client);
        let exec = exec_id.clone();
        async move {
            let _ = client
                .cleanup_call(w::EXEC_STOP, &ExecStopParams { exec, level })
                .await;
        }
    };
    let resizes = {
        let client = Arc::clone(&client);
        let exec = exec_id.clone();
        async move {
            let Some(mut resize) = resize else {
                return future::pending().await;
            };
            while resize.changed().await.is_ok() {
                let size = *resize.borrow_and_update();
                let _ = client
                    .request(w::EXEC_RESIZE, &ExecResizeParams {
                        exec: exec.clone(),
                        size,
                    })
                    .await;
            }
            future::pending::<()>().await;
        }
    };
    let stops = async {
        if let Some(term) = term {
            tokio::select! {
                () = term.cancelled() => stop(StopLevel::Term).await,
                () = kill.cancelled() => {}
            }
        }
        kill.cancelled().await;
        stop(StopLevel::Kill).await;
    };
    tokio::select! {
        () = stops => {}
        () = resizes => {}
    }
}

struct PluginFiles {
    generation: Arc<Generation>,
    id:         SandboxId,
}

#[async_trait]
impl Files for PluginFiles {
    /// Returns once the first bytes (or the whole, possibly empty, result)
    /// arrive, so a missing file fails here rather than mid-read. A later
    /// transfer failure fails the read; it is never a short file.
    async fn get(&self, path: &str, range: Option<FileRange>) -> Result<ByteStream, Error> {
        self.generation.live()?;
        let client = Arc::clone(&self.generation.client);
        let (channel, receiver) = client
            .listener
            .expect()
            .map_err(|error| from_failure(Failure::Local(error)))?;
        let params = FilesGetParams {
            sandbox: self.id.clone(),
            path: path.to_owned(),
            range,
            channel,
        };
        let (chunks, reader) = chunk_stream();
        let (ready, started) = oneshot::channel::<Result<(), Error>>();
        let ready = Arc::new(Mutex::new(Some(ready)));
        let signal = {
            let ready = Arc::clone(&ready);
            move |result: Result<(), Error>| {
                if let Some(ready) = ready.lock().expect("ready lock").take() {
                    let _ = ready.send(result);
                    true
                } else {
                    false
                }
            }
        };
        let producer = tokio::spawn(async move {
            let pump = |Channel { mut reader, .. }: Channel| {
                let chunks = chunks.clone();
                let signal = signal.clone();
                async move {
                    while let Some((kind, payload)) = reader.read().await? {
                        match kind {
                            FrameKind::Stdout => {
                                if payload.is_empty() {
                                    continue;
                                }
                                signal(Ok(()));
                                if chunks.send(Chunk::Data(payload)).await.is_err() {
                                    return Ok(());
                                }
                            }
                            FrameKind::Eof => break,
                            _ => {
                                return Err(Failure::Local(sandbox_driver::Error::Transport(
                                    TransportError::new("unexpected frame on file output"),
                                )));
                            }
                        }
                    }
                    Ok(())
                }
            };
            let call = async { client.request(w::FILES_GET, &params).await.map(|_| ()) };
            let result = client
                .call_with_channel(w::FILES_GET, call, receiver, pump)
                .await
                .map_err(from_failure);
            match result {
                Ok(_) => {
                    signal(Ok(()));
                    let _ = chunks.send(Chunk::Done).await;
                }
                Err(error) => {
                    if !signal(Err(error.clone())) {
                        let _ = chunks.send(Chunk::Failed(error.to_string())).await;
                    }
                }
            }
        });
        let reader = reader.owning(AbortOnDropHandle::new(producer));
        started.await.map_err(|_| Error::Transport {
            message: "file transfer ended without a result".into(),
            outcome: MutationOutcome::Unknown,
        })??;
        Ok(Box::pin(reader))
    }

    async fn put(&self, path: &str, mut bytes: ByteStream) -> Result<(), Error> {
        self.generation.live()?;
        let client = &self.generation.client;
        let (channel, receiver) = client
            .listener
            .expect()
            .map_err(|error| from_failure(Failure::Local(error)))?;
        let params = FilesPutParams {
            sandbox: self.id.clone(),
            path: path.to_owned(),
            channel,
        };
        let pump = |Channel { mut writer, .. }: Channel| async move {
            let mut buffer = vec![0; 64 * 1024];
            loop {
                let count = bytes.read(&mut buffer).await.map_err(|error| {
                    Failure::Local(sandbox_driver::Error::io("reading the upload", error))
                })?;
                if count == 0 {
                    break;
                }
                writer.write(FrameKind::Stdin, &buffer[..count]).await?;
            }
            writer.finish().await?;
            Ok(())
        };
        let call = async { client.request(w::FILES_PUT, &params).await.map(|_| ()) };
        client
            .call_with_channel(w::FILES_PUT, call, receiver, pump)
            .await
            .map_err(from_failure)?;
        Ok(())
    }

    async fn list(&self, path: &str, depth: u32) -> Result<Vec<FileEntry>, Error> {
        self.generation
            .call(w::FILES_LIST, &FilesListParams {
                sandbox: self.id.clone(),
                path: path.to_owned(),
                depth,
            })
            .await
    }
}

struct PluginPorts {
    generation: Arc<Generation>,
    id:         SandboxId,
}

#[async_trait]
impl Ports for PluginPorts {
    async fn expose(&self, port: NonZeroU16, options: Expose) -> Result<Exposure, Error> {
        self.generation
            .call(w::PORTS_EXPOSE, &PortParams {
                sandbox: self.id.clone(),
                port,
                options: Some(options),
            })
            .await
    }

    async fn release(&self, port: NonZeroU16) -> Result<(), Error> {
        let _: m::Empty = self
            .generation
            .call(w::PORTS_RELEASE, &PortParams {
                sandbox: self.id.clone(),
                port,
                options: None,
            })
            .await?;
        Ok(())
    }
}

fn decode<R: DeserializeOwned>(method: &str, value: Value) -> Result<R, Error> {
    serde_json::from_value(value).map_err(|_| Error::Transport {
        message: format!("the plugin returned an invalid {method} result"),
        outcome: MutationOutcome::Unknown,
    })
}

fn not_started(entry: &ProviderName, message: &str) -> Error {
    Error::Unavailable {
        message: format!("provider entry {entry}: {message}"),
        outcome: MutationOutcome::NotStarted,
    }
}

/// A plugin's own refusal (bad config, missing secret) passes through; an
/// older plugin that cannot speak this version is a setup error, not a crash.
fn initialize_error(entry: &ProviderName, failure: Failure) -> Error {
    match failure {
        Failure::Remote(error)
            if error
                .data
                .as_ref()
                .is_some_and(|data| data.report.kind == "contract") =>
        {
            from_failure(Failure::Remote(error))
        }
        Failure::Remote(error) => not_started(
            entry,
            &format!(
                "the plugin does not speak protocol version {}: {}",
                w::PROTOCOL_VERSION,
                error.message
            ),
        ),
        Failure::Local(error) => not_started(
            entry,
            &format!("the plugin ended before initializing: {error}"),
        ),
    }
}
