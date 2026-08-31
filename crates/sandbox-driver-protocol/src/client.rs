//! Host-side client: adapts a JSON-RPC plugin back into the
//! [`SandboxProvider`] / [`Sandbox`] traits.

use std::collections::{BTreeMap, HashMap};
use std::path::Path;
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use sandbox_driver::{
    Capabilities, CheckpointId, CheckpointOptions, DirEntry, Error, EventCallback, Exec,
    ExecControls, ExecResult, ExecSpec, ExecStreamingResult, FileMetadata, Filesystem, ForkOptions,
    HealthStatus, LifecycleTimers, LogSink, LogSource, Logs, NetworkPolicy, OutputStream,
    PlatformInfo, PreviewUrl, PreviewUrls, ProviderHealth, ProviderKind, Pty, PtyOptions,
    PtySession, PtySize, Resources, Result, Sandbox, SandboxFilter, SandboxId,
    SandboxSnapshotOptions, SandboxSpec, SandboxStatus, SnapshotFilter, SnapshotId,
    SnapshotProvider, SnapshotSpec, SnapshotStatus, SpawnSpec, SshAccess, SshAccessInfo,
    StderrTail, StdioProcess, StdioProcessHandle, Termination, Vnc, VncConnection, VolumeId,
    VolumeProvider, VolumeSpec, VolumeStatus, WebTerminal,
};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;
use tokio::io::{
    AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, duplex,
};
use tokio::process::{Child, Command};
use tokio::runtime::Handle as RuntimeHandle;
use tokio::sync::{Mutex as AsyncMutex, OnceCell, mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio::{fs as tokio_fs, time};

use crate::methods as m;
use crate::wire::{Message, decode_bytes, encode_bytes};

/// A provider served by a JSON-RPC plugin over a byte stream.
///
/// `connect` performs the `initialize` handshake and returns a provider
/// whose capabilities are the plugin's declared set. The background read
/// and write tasks end when the transport closes or the provider is
/// dropped.
pub struct PluginProvider {
    client:       Arc<Client>,
    kind:         ProviderKind,
    capabilities: Capabilities,
    snapshots:    Option<ProviderSnapshots>,
    volumes:      Option<ProviderVolumes>,
    /// The plugin child process, when this provider spawned one.
    child:        Option<Mutex<Option<Child>>>,
}

impl PluginProvider {
    pub async fn connect(
        reader: impl AsyncRead + Unpin + Send + 'static,
        writer: impl AsyncWrite + Unpin + Send + 'static,
    ) -> Result<Self> {
        let client = Client::start(reader, writer);
        let result: m::InitializeResult = client
            .call(m::INITIALIZE, &m::InitializeParams {
                protocol_version: m::PROTOCOL_VERSION,
            })
            .await?;
        if result.protocol_version != m::PROTOCOL_VERSION {
            return Err(Error::invalid_spec(
                "protocol_version",
                format!(
                    "host speaks protocol version {} but the plugin answered {}",
                    m::PROTOCOL_VERSION,
                    result.protocol_version
                ),
            ));
        }
        let mut capabilities = result.capabilities;
        mask_wire_capabilities(&mut capabilities);
        let snapshots = capabilities.snapshots.is_some().then(|| ProviderSnapshots {
            client: Arc::clone(&client),
        });
        let volumes = capabilities.volumes.is_some().then(|| ProviderVolumes {
            client: Arc::clone(&client),
        });
        Ok(Self {
            client,
            kind: result.provider.kind,
            capabilities,
            snapshots,
            volumes,
            child: None,
        })
    }

    /// Spawns a plugin binary as a child process and connects over its
    /// stdin/stdout.
    ///
    /// The caller configures the command (arguments, environment
    /// scrubbing, working directory — transport trust is host policy);
    /// this constructor pipes stdio, leaves stderr inherited so plugin
    /// logs reach the host's stderr, and marks the child kill-on-drop.
    /// [`PluginProvider::shutdown`] asks the plugin to exit and reaps it,
    /// killing after a grace period.
    pub async fn spawn(mut command: Command) -> Result<Self> {
        command.stdin(Stdio::piped());
        command.stdout(Stdio::piped());
        command.kill_on_drop(true);
        let mut child = command
            .spawn()
            .map_err(|error| Error::io("spawning plugin process", error))?;
        let stdin = child.stdin.take().expect("stdin was piped");
        let stdout = child.stdout.take().expect("stdout was piped");
        let mut provider = Self::connect(stdout, stdin).await?;
        provider.child = Some(Mutex::new(Some(child)));
        Ok(provider)
    }

    /// Asks the plugin to shut down cleanly and, for a spawned plugin,
    /// reaps the child — killing it after a grace period if it lingers.
    pub async fn shutdown(&self) -> Result<()> {
        let _: m::Empty = self.client.call(m::SHUTDOWN, &m::Empty).await?;
        let child = self
            .child
            .as_ref()
            .and_then(|slot| slot.lock().expect("child lock").take());
        if let Some(mut child) = child {
            if time::timeout(Duration::from_secs(5), child.wait())
                .await
                .is_err()
            {
                let _ = child.kill().await;
                let _ = child.wait().await;
            }
        }
        Ok(())
    }

    fn wrap_handle(
        &self,
        mut info: m::HandleInfo,
        events: Option<EventCallback>,
    ) -> Arc<dyn Sandbox> {
        mask_wire_capabilities(&mut info.capabilities);
        let id = info.status.id.clone();
        if let Some(callback) = events {
            self.client
                .event_callbacks
                .lock()
                .expect("event callbacks lock")
                .insert(id.as_str().to_owned(), callback);
        }
        Arc::new(SandboxHandle {
            client:            Arc::clone(&self.client),
            id:                id.clone(),
            capabilities:      info.capabilities,
            working_directory: info.working_directory,
            runtime_directory: info.runtime_directory,
            exec:              SandboxExec {
                client:     Arc::clone(&self.client),
                sandbox_id: id.clone(),
            },
            access:            SandboxAccess {
                client:     Arc::clone(&self.client),
                sandbox_id: id.clone(),
            },
            pty:               SandboxPty {
                client:     Arc::clone(&self.client),
                sandbox_id: id.clone(),
            },
            logs:              SandboxLogs {
                client:     Arc::clone(&self.client),
                sandbox_id: id.clone(),
            },
            fs:                SandboxFs {
                client:     Arc::clone(&self.client),
                sandbox_id: id,
            },
        })
    }
}

#[async_trait]
impl sandbox_driver::SandboxProvider for PluginProvider {
    fn kind(&self) -> &ProviderKind {
        &self.kind
    }

    fn capabilities(&self) -> &Capabilities {
        &self.capabilities
    }

    async fn create(
        &self,
        spec: &SandboxSpec,
        events: Option<EventCallback>,
    ) -> Result<Arc<dyn Sandbox>> {
        // A caller that wants events gets them from the first moment of
        // the create, before a sandbox id exists: the operation id
        // routes host/event notifications until wrap_handle re-registers
        // the callback under the sandbox id.
        let operation_id = events.as_ref().map(|callback| {
            let id = format!(
                "op-{}",
                self.client.next_operation.fetch_add(1, Ordering::Relaxed)
            );
            self.client
                .operation_callbacks
                .lock()
                .expect("operation callbacks lock")
                .insert(id.clone(), Arc::clone(callback));
            id
        });
        let outcome: Result<m::HandleInfo> = self
            .client
            .call(m::SANDBOX_CREATE, &m::CreateParams {
                spec:         spec.clone(),
                operation_id: operation_id.clone(),
            })
            .await;
        if let Some(operation_id) = operation_id {
            self.client
                .operation_callbacks
                .lock()
                .expect("operation callbacks lock")
                .remove(&operation_id);
        }
        Ok(self.wrap_handle(outcome?, events))
    }

    async fn attach(
        &self,
        id: &SandboxId,
        events: Option<EventCallback>,
    ) -> Result<Arc<dyn Sandbox>> {
        let info: m::HandleInfo = self
            .client
            .call(m::SANDBOX_ATTACH, &m::AttachParams {
                sandbox_id: id.as_str().to_owned(),
            })
            .await?;
        Ok(self.wrap_handle(info, events))
    }

    async fn undelete(
        &self,
        id: &SandboxId,
        events: Option<EventCallback>,
    ) -> Result<Arc<dyn Sandbox>> {
        let info: m::HandleInfo = self
            .client
            .call(m::SANDBOX_UNDELETE, &m::AttachParams {
                sandbox_id: id.as_str().to_owned(),
            })
            .await?;
        Ok(self.wrap_handle(info, events))
    }

    async fn list(&self, filter: &SandboxFilter) -> Result<Vec<SandboxStatus>> {
        let result: m::ListResult = self
            .client
            .call(m::SANDBOX_LIST, &m::ListParams {
                filter: filter.clone(),
            })
            .await?;
        Ok(result.sandboxes)
    }

    async fn health(&self) -> Result<ProviderHealth> {
        match self
            .client
            .call::<_, m::HealthResult>(m::PROVIDER_HEALTH, &m::Empty)
            .await
        {
            Ok(result) => Ok(result.health),
            // An older plugin without provider/health answers -32601;
            // that is "no health check", not a failed one.
            Err(Error::Provider(provider)) if provider.code.as_deref() == Some("-32601") => {
                Ok(ProviderHealth::new(HealthStatus::Unknown))
            }
            Err(error) => Err(error),
        }
    }

    fn snapshots(&self) -> Option<&dyn SnapshotProvider> {
        self.snapshots
            .as_ref()
            .map(|service| service as &dyn SnapshotProvider)
    }

    fn volumes(&self) -> Option<&dyn VolumeProvider> {
        self.volumes
            .as_ref()
            .map(|service| service as &dyn VolumeProvider)
    }
}

/// Snapshot service backed by the plugin.
struct ProviderSnapshots {
    client: Arc<Client>,
}

#[async_trait]
impl SnapshotProvider for ProviderSnapshots {
    async fn create(&self, spec: &SnapshotSpec) -> Result<SnapshotId> {
        let result: m::SnapshotIdResult = self
            .client
            .call(m::SNAPSHOT_CREATE, &m::SnapshotCreateParams {
                spec: spec.clone(),
            })
            .await?;
        SnapshotId::try_new(result.snapshot_id)
            .map_err(|error| Error::invalid_spec("snapshot_id", error.to_string()))
    }

    async fn get(&self, id: &SnapshotId) -> Result<SnapshotStatus> {
        let result: m::SnapshotStatusResult = self
            .client
            .call(m::SNAPSHOT_GET, &m::SnapshotIdParams {
                snapshot_id: id.as_str().to_owned(),
            })
            .await?;
        Ok(result.status)
    }

    async fn list(&self, filter: &SnapshotFilter) -> Result<Vec<SnapshotStatus>> {
        let result: m::SnapshotListResult = self
            .client
            .call(m::SNAPSHOT_LIST, &m::SnapshotListParams {
                filter: filter.clone(),
            })
            .await?;
        Ok(result.snapshots)
    }

    async fn delete(&self, id: &SnapshotId) -> Result<()> {
        let _: m::Empty = self
            .client
            .call(m::SNAPSHOT_DELETE, &m::SnapshotIdParams {
                snapshot_id: id.as_str().to_owned(),
            })
            .await?;
        Ok(())
    }

    async fn build_logs(&self, id: &SnapshotId, follow: bool, sink: LogSink) -> Result<()> {
        let stream_id = self.client.next_stream_id("snapshot");
        follow_log_stream(
            &self.client,
            m::SNAPSHOT_BUILD_LOGS,
            &m::SnapshotBuildLogsParams {
                snapshot_id: id.as_str().to_owned(),
                stream_id: stream_id.clone(),
                follow,
            },
            &stream_id,
            sink,
        )
        .await
    }

    async fn activate(&self, id: &SnapshotId) -> Result<()> {
        let _: m::Empty = self
            .client
            .call(m::SNAPSHOT_ACTIVATE, &m::SnapshotIdParams {
                snapshot_id: id.as_str().to_owned(),
            })
            .await?;
        Ok(())
    }

    async fn deactivate(&self, id: &SnapshotId) -> Result<()> {
        let _: m::Empty = self
            .client
            .call(m::SNAPSHOT_DEACTIVATE, &m::SnapshotIdParams {
                snapshot_id: id.as_str().to_owned(),
            })
            .await?;
        Ok(())
    }
}

/// Volume service backed by the plugin.
struct ProviderVolumes {
    client: Arc<Client>,
}

#[async_trait]
impl VolumeProvider for ProviderVolumes {
    async fn create(&self, spec: &VolumeSpec) -> Result<VolumeId> {
        let result: m::VolumeIdResult = self
            .client
            .call(m::VOLUME_CREATE, &m::VolumeCreateParams {
                spec: spec.clone(),
            })
            .await?;
        VolumeId::try_new(result.volume_id)
            .map_err(|error| Error::invalid_spec("volume_id", error.to_string()))
    }

    async fn get(&self, id: &VolumeId) -> Result<VolumeStatus> {
        let result: m::VolumeStatusResult = self
            .client
            .call(m::VOLUME_GET, &m::VolumeIdParams {
                volume_id: id.as_str().to_owned(),
            })
            .await?;
        Ok(result.status)
    }

    async fn list(&self) -> Result<Vec<VolumeStatus>> {
        let result: m::VolumeListResult = self.client.call(m::VOLUME_LIST, &m::Empty).await?;
        Ok(result.volumes)
    }

    async fn delete(&self, id: &VolumeId) -> Result<()> {
        let _: m::Empty = self
            .client
            .call(m::VOLUME_DELETE, &m::VolumeIdParams {
                volume_id: id.as_str().to_owned(),
            })
            .await?;
        Ok(())
    }
}

/// Preview-URL and SSH access backed by the plugin.
struct SandboxAccess {
    client:     Arc<Client>,
    sandbox_id: SandboxId,
}

#[async_trait]
impl PreviewUrls for SandboxAccess {
    async fn preview_url(&self, port: u16) -> Result<PreviewUrl> {
        let result: m::PreviewUrlResult = self
            .client
            .call(m::ACCESS_PREVIEW_URL, &m::PreviewUrlParams {
                sandbox_id: self.sandbox_id.as_str().to_owned(),
                port,
            })
            .await?;
        Ok(result.preview)
    }

    async fn signed_preview_url(&self, port: u16, expires_in: Duration) -> Result<PreviewUrl> {
        let result: m::PreviewUrlResult = self
            .client
            .call(m::ACCESS_SIGNED_PREVIEW_URL, &m::SignedPreviewUrlParams {
                sandbox_id: self.sandbox_id.as_str().to_owned(),
                port,
                expires_in_ms: u64::try_from(expires_in.as_millis()).unwrap_or(u64::MAX),
            })
            .await?;
        Ok(result.preview)
    }
}

#[async_trait]
impl SshAccess for SandboxAccess {
    async fn create_ssh_access(&self, ttl: Option<Duration>) -> Result<SshAccessInfo> {
        let result: m::SshCreateResult = self
            .client
            .call(m::ACCESS_SSH_CREATE, &m::SshCreateParams {
                sandbox_id: self.sandbox_id.as_str().to_owned(),
                ttl_ms:     ttl.map(|ttl| u64::try_from(ttl.as_millis()).unwrap_or(u64::MAX)),
            })
            .await?;
        Ok(result.access)
    }

    async fn revoke_ssh_access(&self, token: &str) -> Result<()> {
        let _: m::Empty = self
            .client
            .call(m::ACCESS_SSH_REVOKE, &m::SshRevokeParams {
                sandbox_id: self.sandbox_id.as_str().to_owned(),
                token:      token.to_owned(),
            })
            .await?;
        Ok(())
    }
}

#[async_trait]
impl WebTerminal for SandboxAccess {
    async fn web_terminal_url(&self) -> Result<String> {
        let result: m::WebTerminalResult = self
            .client
            .call(m::ACCESS_WEB_TERMINAL, &m::SandboxIdParams {
                sandbox_id: self.sandbox_id.as_str().to_owned(),
            })
            .await?;
        Ok(result.url)
    }
}

#[async_trait]
impl Vnc for SandboxAccess {
    async fn vnc_connection(&self) -> Result<VncConnection> {
        let result: m::VncResult = self
            .client
            .call(m::ACCESS_VNC, &m::SandboxIdParams {
                sandbox_id: self.sandbox_id.as_str().to_owned(),
            })
            .await?;
        Ok(result.connection)
    }
}

/// Removes capabilities the protocol cannot deliver through the wire.
/// Native search/git/service passthrough and local shell commands remain
/// process-local. The normalized stdio, PTY, logs, browser access,
/// snapshots, volumes, preview URLs, and SSH facets cross the wire.
fn mask_wire_capabilities(capabilities: &mut Capabilities) {
    capabilities.search.native = false;
    capabilities.git.native = false;
    capabilities.services.native = false;
    capabilities.access.shell_command = false;
}

/// One in-flight chunk of streamed exec output.
type ExecChunk = (OutputStream, Vec<u8>);

/// Raw bytes per fs/read / fs/write message during composed uploads and
/// downloads (the base64 payload is 4/3 of this on the wire).
const TRANSFER_CHUNK_BYTES: usize = 4 * 1024 * 1024;

/// Chunks buffered per exec before the reader backpressures. Deep enough
/// that a slow consumer of one stream cannot stall unrelated responses in
/// any realistic run; full-queue blocking is the documented residual
/// coupling of a single shared pipe (the side-channel transport lifts it).
const EXEC_STREAM_QUEUE: usize = 1024;

/// Request/response correlation plus notification routing.
///
/// The reader task never awaits consumer code: exec output is handed to a
/// per-exec ordered queue drained by a pump task that owns the caller's
/// sink, so one slow consumer delays only its own stream.
struct Client {
    outbound:            mpsc::Sender<Message>,
    next_id:             AtomicU64,
    next_exec:           AtomicU64,
    next_stream:         AtomicU64,
    next_operation:      AtomicU64,
    /// Set when either transport task ends; every pending and future call
    /// fails fast instead of waiting on a dead pipe.
    closed:              AtomicBool,
    pending:             Mutex<HashMap<u64, oneshot::Sender<Result<Value>>>>,
    exec_streams:        Mutex<HashMap<String, mpsc::Sender<ExecChunk>>>,
    log_streams:         Mutex<HashMap<String, mpsc::Sender<Vec<u8>>>>,
    event_callbacks:     Mutex<HashMap<String, EventCallback>>,
    /// Callbacks for in-flight creates, keyed by operation id, so events
    /// arrive before a sandbox id exists.
    operation_callbacks: Mutex<HashMap<String, EventCallback>>,
}

impl Client {
    fn start(
        reader: impl AsyncRead + Unpin + Send + 'static,
        writer: impl AsyncWrite + Unpin + Send + 'static,
    ) -> Arc<Self> {
        let (outbound, mut outbound_rx) = mpsc::channel::<Message>(256);
        let client = Arc::new(Self {
            outbound,
            next_id: AtomicU64::new(1),
            next_exec: AtomicU64::new(1),
            next_stream: AtomicU64::new(1),
            next_operation: AtomicU64::new(1),
            closed: AtomicBool::new(false),
            pending: Mutex::new(HashMap::new()),
            exec_streams: Mutex::new(HashMap::new()),
            log_streams: Mutex::new(HashMap::new()),
            event_callbacks: Mutex::new(HashMap::new()),
            operation_callbacks: Mutex::new(HashMap::new()),
        });

        let writer_client = Arc::clone(&client);
        tokio::spawn(async move {
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
            writer_client.mark_closed();
        });

        let reader_client = Arc::clone(&client);
        tokio::spawn(async move {
            let mut lines = BufReader::new(reader).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                if line.trim().is_empty() {
                    continue;
                }
                let Ok(message) = serde_json::from_str::<Message>(&line) else {
                    continue;
                };
                reader_client.route(message).await;
            }
            reader_client.mark_closed();
        });

        client
    }

    /// Marks the transport dead and fails everything pending. Called by
    /// both transport tasks; also re-checked by `call` after registering,
    /// closing the race where a call lands just after the drain.
    fn mark_closed(&self) {
        self.closed.store(true, Ordering::SeqCst);
        let pending: Vec<_> = {
            let mut pending = self.pending.lock().expect("pending lock");
            pending.drain().collect()
        };
        for (_, sender) in pending {
            let _ = sender.send(Err(Error::invalid_spec("transport", "connection closed")));
        }
        self.exec_streams.lock().expect("exec streams lock").clear();
        self.log_streams.lock().expect("log streams lock").clear();
    }

    fn next_stream_id(&self, prefix: &str) -> String {
        format!(
            "{prefix}-{}",
            self.next_stream.fetch_add(1, Ordering::Relaxed)
        )
    }

    async fn route(&self, message: Message) {
        if let Some(id) = message.id {
            let sender = self.pending.lock().expect("pending lock").remove(&id);
            if let Some(sender) = sender {
                let outcome = match (message.result, message.error) {
                    (_, Some(error)) => Err(error.into_error()),
                    (Some(result), None) => Ok(result),
                    (None, None) => Ok(Value::Null),
                };
                let _ = sender.send(outcome);
            }
            return;
        }
        let Some(method) = message.method.as_deref() else {
            return;
        };
        let params = message.params.unwrap_or(Value::Null);
        match method {
            m::EXEC_OUTPUT => {
                let Ok(notification) = serde_json::from_value::<m::ExecOutputNotification>(params)
                else {
                    return;
                };
                let queue = self
                    .exec_streams
                    .lock()
                    .expect("exec streams lock")
                    .get(&notification.exec_id)
                    .cloned();
                if let (Some(queue), Ok(chunk)) = (queue, decode_bytes(&notification.data_b64)) {
                    // A send failure means the exec already resolved and
                    // unregistered; dropping the late chunk is correct.
                    let _ = queue.send((notification.stream, chunk)).await;
                }
            }
            m::LOG_OUTPUT => {
                let Ok(notification) = serde_json::from_value::<m::LogOutputNotification>(params)
                else {
                    return;
                };
                let queue = self
                    .log_streams
                    .lock()
                    .expect("log streams lock")
                    .get(&notification.stream_id)
                    .cloned();
                if let (Some(queue), Ok(chunk)) = (queue, decode_bytes(&notification.data_b64)) {
                    let _ = queue.send(chunk).await;
                }
            }
            m::HOST_EVENT => {
                let Ok(notification) = serde_json::from_value::<m::HostEventNotification>(params)
                else {
                    return;
                };
                // Operation routing first: during a create the same
                // callback may be registered under both keys, and the
                // event must be delivered exactly once.
                let callback = notification
                    .operation_id
                    .as_ref()
                    .and_then(|operation_id| {
                        self.operation_callbacks
                            .lock()
                            .expect("operation callbacks lock")
                            .get(operation_id)
                            .cloned()
                    })
                    .or_else(|| {
                        self.event_callbacks
                            .lock()
                            .expect("event callbacks lock")
                            .get(&notification.sandbox_id)
                            .cloned()
                    });
                if let Some(callback) = callback {
                    callback(notification.event);
                }
            }
            _ => {}
        }
    }

    async fn call<P: Serialize, R: DeserializeOwned>(&self, method: &str, params: &P) -> Result<R> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let params = serde_json::to_value(params)
            .map_err(|error| Error::invalid_spec("params", error.to_string()))?;
        let (sender, receiver) = oneshot::channel();
        self.pending
            .lock()
            .expect("pending lock")
            .insert(id, sender);
        if self.closed.load(Ordering::SeqCst) {
            // The transport may have died between the drain and our
            // registration; drain again so this call cannot hang.
            self.mark_closed();
        }
        if let Err(_send_error) = self
            .outbound
            .send(Message::request(id, method, params))
            .await
        {
            self.pending.lock().expect("pending lock").remove(&id);
            return Err(Error::invalid_spec("transport", "connection closed"));
        }
        let value = receiver
            .await
            .map_err(|_| Error::invalid_spec("transport", "connection closed"))??;
        serde_json::from_value(value)
            .map_err(|error| Error::invalid_spec("result", error.to_string()))
    }
}

struct StreamCancelGuard {
    client:    Arc<Client>,
    stream_id: String,
    armed:     bool,
}

impl Drop for StreamCancelGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let client = Arc::clone(&self.client);
        let stream_id = self.stream_id.clone();
        // The follow future is normally dropped inside the runtime, but a
        // teardown-time drop must not panic; without a runtime the plugin
        // connection is going away with the stream anyway.
        if let Ok(handle) = RuntimeHandle::try_current() {
            handle.spawn(async move {
                let _: Result<m::Empty> = client
                    .call(m::STREAM_CANCEL, &m::StreamIdParams { stream_id })
                    .await;
            });
        }
    }
}

async fn follow_log_stream<P: Serialize>(
    client: &Arc<Client>,
    method: &str,
    params: &P,
    stream_id: &str,
    sink: LogSink,
) -> Result<()> {
    let (queue, mut receiver) = mpsc::channel::<Vec<u8>>(EXEC_STREAM_QUEUE);
    client
        .log_streams
        .lock()
        .expect("log streams lock")
        .insert(stream_id.to_owned(), queue);
    let mut guard = StreamCancelGuard {
        client:    Arc::clone(client),
        stream_id: stream_id.to_owned(),
        armed:     true,
    };
    let mut call = Box::pin(client.call::<_, m::Empty>(method, params));
    let mut queue_open = true;
    loop {
        tokio::select! {
            outcome = &mut call => {
                client
                    .log_streams
                    .lock()
                    .expect("log streams lock")
                    .remove(stream_id);
                while let Ok(chunk) = receiver.try_recv() {
                    sink(chunk).await?;
                }
                guard.armed = false;
                return outcome.map(|_| ());
            }
            chunk = receiver.recv(), if queue_open => {
                match chunk {
                    Some(chunk) => {
                        if let Err(error) = sink(chunk).await {
                            client
                                .log_streams
                                .lock()
                                .expect("log streams lock")
                                .remove(stream_id);
                            return Err(error);
                        }
                    }
                    None => queue_open = false,
                }
            }
        }
    }
}

/// A sandbox handle backed by the plugin.
struct SandboxHandle {
    client:            Arc<Client>,
    id:                SandboxId,
    capabilities:      Capabilities,
    working_directory: String,
    runtime_directory: Option<String>,
    exec:              SandboxExec,
    access:            SandboxAccess,
    pty:               SandboxPty,
    logs:              SandboxLogs,
    fs:                SandboxFs,
}

impl SandboxHandle {
    fn id_params(&self) -> m::SandboxIdParams {
        m::SandboxIdParams {
            sandbox_id: self.id.as_str().to_owned(),
        }
    }

    async fn simple(&self, method: &str) -> Result<()> {
        let _: m::Empty = self.client.call(method, &self.id_params()).await?;
        Ok(())
    }
}

#[async_trait]
impl Sandbox for SandboxHandle {
    fn id(&self) -> &SandboxId {
        &self.id
    }

    fn capabilities(&self) -> &Capabilities {
        &self.capabilities
    }

    async fn describe(&self) -> Result<SandboxStatus> {
        let result: m::StatusResult = self
            .client
            .call(m::SANDBOX_DESCRIBE, &self.id_params())
            .await?;
        Ok(result.status)
    }

    fn working_directory(&self) -> &str {
        &self.working_directory
    }

    fn runtime_directory(&self) -> Option<&str> {
        self.runtime_directory.as_deref()
    }

    async fn platform_info(&self) -> Result<PlatformInfo> {
        let result: m::PlatformInfoResult = self
            .client
            .call(m::SANDBOX_PLATFORM_INFO, &self.id_params())
            .await?;
        Ok(result.platform)
    }

    async fn start(&self) -> Result<()> {
        self.simple(m::SANDBOX_START).await
    }

    async fn stop(&self) -> Result<()> {
        self.simple(m::SANDBOX_STOP).await
    }

    async fn delete(&self) -> Result<()> {
        self.simple(m::SANDBOX_DELETE).await
    }

    async fn pause(&self) -> Result<()> {
        self.simple(m::SANDBOX_PAUSE).await
    }

    async fn resume(&self) -> Result<()> {
        self.simple(m::SANDBOX_RESUME).await
    }

    async fn archive(&self) -> Result<()> {
        self.simple(m::SANDBOX_ARCHIVE).await
    }

    async fn recover(&self) -> Result<()> {
        self.simple(m::SANDBOX_RECOVER).await
    }

    async fn refresh_activity(&self) -> Result<()> {
        self.simple(m::SANDBOX_REFRESH_ACTIVITY).await
    }

    async fn fork(&self, options: &ForkOptions) -> Result<Arc<dyn Sandbox>> {
        let info: m::HandleInfo = self
            .client
            .call(m::SANDBOX_FORK, &m::ForkParams {
                sandbox_id: self.id.as_str().to_owned(),
                options:    options.clone(),
            })
            .await?;
        let id = info.status.id.clone();
        Ok(Arc::new(Self {
            client:            Arc::clone(&self.client),
            id:                id.clone(),
            capabilities:      info.capabilities,
            working_directory: info.working_directory,
            runtime_directory: info.runtime_directory,
            exec:              SandboxExec {
                client:     Arc::clone(&self.client),
                sandbox_id: id.clone(),
            },
            access:            SandboxAccess {
                client:     Arc::clone(&self.client),
                sandbox_id: id.clone(),
            },
            pty:               SandboxPty {
                client:     Arc::clone(&self.client),
                sandbox_id: id.clone(),
            },
            logs:              SandboxLogs {
                client:     Arc::clone(&self.client),
                sandbox_id: id.clone(),
            },
            fs:                SandboxFs {
                client:     Arc::clone(&self.client),
                sandbox_id: id,
            },
        }))
    }

    async fn checkpoint(&self, options: &CheckpointOptions) -> Result<CheckpointId> {
        let result: m::CheckpointResult = self
            .client
            .call(m::SANDBOX_CHECKPOINT, &m::CheckpointParams {
                sandbox_id: self.id.as_str().to_owned(),
                options:    options.clone(),
            })
            .await?;
        CheckpointId::try_new(result.checkpoint_id)
            .map_err(|error| Error::invalid_spec("checkpoint_id", error.to_string()))
    }

    async fn restore_checkpoint(&self, checkpoint: &CheckpointId) -> Result<()> {
        let _: m::Empty = self
            .client
            .call(m::SANDBOX_RESTORE_CHECKPOINT, &m::RestoreCheckpointParams {
                sandbox_id:    self.id.as_str().to_owned(),
                checkpoint_id: checkpoint.as_str().to_owned(),
            })
            .await?;
        Ok(())
    }

    async fn resize(&self, resources: &Resources) -> Result<()> {
        let _: m::Empty = self
            .client
            .call(m::SANDBOX_RESIZE, &m::ResizeParams {
                sandbox_id: self.id.as_str().to_owned(),
                resources:  *resources,
            })
            .await?;
        Ok(())
    }

    async fn snapshot(&self, options: &SandboxSnapshotOptions) -> Result<SnapshotId> {
        let result: m::SnapshotResult = self
            .client
            .call(m::SANDBOX_SNAPSHOT, &m::SnapshotParams {
                sandbox_id: self.id.as_str().to_owned(),
                options:    options.clone(),
            })
            .await?;
        SnapshotId::try_new(result.snapshot_id)
            .map_err(|error| Error::invalid_spec("snapshot_id", error.to_string()))
    }

    async fn set_timers(&self, timers: &LifecycleTimers) -> Result<()> {
        let _: m::Empty = self
            .client
            .call(m::SANDBOX_SET_TIMERS, &m::SetTimersParams {
                sandbox_id: self.id.as_str().to_owned(),
                timers:     *timers,
            })
            .await?;
        Ok(())
    }

    async fn set_labels(&self, labels: &BTreeMap<String, String>) -> Result<()> {
        let _: m::Empty = self
            .client
            .call(m::SANDBOX_SET_LABELS, &m::SetLabelsParams {
                sandbox_id: self.id.as_str().to_owned(),
                labels:     labels.clone(),
            })
            .await?;
        Ok(())
    }

    async fn update_network(&self, policy: &NetworkPolicy) -> Result<()> {
        let _: m::Empty = self
            .client
            .call(m::SANDBOX_UPDATE_NETWORK, &m::UpdateNetworkParams {
                sandbox_id: self.id.as_str().to_owned(),
                network:    policy.clone(),
            })
            .await?;
        Ok(())
    }

    fn exec(&self) -> &dyn Exec {
        &self.exec
    }

    fn fs(&self) -> &dyn Filesystem {
        &self.fs
    }

    fn preview_urls(&self) -> Option<&dyn PreviewUrls> {
        self.capabilities
            .access
            .preview_urls
            .then_some(&self.access as &dyn PreviewUrls)
    }

    fn ssh(&self) -> Option<&dyn SshAccess> {
        self.capabilities
            .access
            .ssh
            .then_some(&self.access as &dyn SshAccess)
    }

    fn pty(&self) -> Option<&dyn Pty> {
        self.capabilities
            .pty
            .as_ref()
            .map(|_| &self.pty as &dyn Pty)
    }

    fn logs(&self) -> Option<&dyn Logs> {
        self.capabilities
            .logs
            .as_ref()
            .map(|_| &self.logs as &dyn Logs)
    }

    fn web_terminal(&self) -> Option<&dyn WebTerminal> {
        self.capabilities
            .access
            .web_terminal
            .then_some(&self.access as &dyn WebTerminal)
    }

    fn vnc(&self) -> Option<&dyn Vnc> {
        self.capabilities
            .access
            .vnc
            .then_some(&self.access as &dyn Vnc)
    }
}

struct SandboxPty {
    client:     Arc<Client>,
    sandbox_id: SandboxId,
}

#[async_trait]
impl Pty for SandboxPty {
    async fn open(&self, options: &PtyOptions) -> Result<Box<dyn PtySession>> {
        let pty_id = self.client.next_stream_id("pty");
        let _: m::Empty = self
            .client
            .call(m::PTY_OPEN, &m::PtyOpenParams {
                sandbox_id: self.sandbox_id.as_str().to_owned(),
                pty_id:     pty_id.clone(),
                options:    options.clone(),
            })
            .await?;
        Ok(Box::new(RemotePtySession {
            client: Arc::clone(&self.client),
            pty_id,
        }))
    }
}

struct RemotePtySession {
    client: Arc<Client>,
    pty_id: String,
}

#[async_trait]
impl PtySession for RemotePtySession {
    async fn write_input(&self, bytes: &[u8]) -> Result<()> {
        let _: m::Empty = self
            .client
            .call(m::PTY_INPUT, &m::PtyInputParams {
                pty_id:   self.pty_id.clone(),
                data_b64: encode_bytes(bytes),
            })
            .await?;
        Ok(())
    }

    async fn read_output(&self) -> Result<Option<Vec<u8>>> {
        let result: m::PtyOutputResult = self
            .client
            .call(m::PTY_OUTPUT, &m::PtyIdParams {
                pty_id: self.pty_id.clone(),
            })
            .await?;
        result.data_b64.map(|data| decode_bytes(&data)).transpose()
    }

    async fn resize(&self, size: PtySize) -> Result<()> {
        let _: m::Empty = self
            .client
            .call(m::PTY_RESIZE, &m::PtyResizeParams {
                pty_id: self.pty_id.clone(),
                size,
            })
            .await?;
        Ok(())
    }

    async fn close(&self) -> Result<()> {
        let _: m::Empty = self
            .client
            .call(m::PTY_CLOSE, &m::PtyIdParams {
                pty_id: self.pty_id.clone(),
            })
            .await?;
        Ok(())
    }
}

struct SandboxLogs {
    client:     Arc<Client>,
    sandbox_id: SandboxId,
}

#[async_trait]
impl Logs for SandboxLogs {
    async fn follow(&self, source: LogSource, sink: LogSink) -> Result<()> {
        let stream_id = self.client.next_stream_id("logs");
        follow_log_stream(
            &self.client,
            m::LOGS_FOLLOW,
            &m::LogsFollowParams {
                sandbox_id: self.sandbox_id.as_str().to_owned(),
                stream_id: stream_id.clone(),
                source,
            },
            &stream_id,
            sink,
        )
        .await
    }
}

struct SandboxExec {
    client:     Arc<Client>,
    sandbox_id: SandboxId,
}

#[async_trait]
impl Exec for SandboxExec {
    async fn run(&self, spec: &ExecSpec) -> Result<ExecResult> {
        let result: m::ExecResultDto = self
            .client
            .call(m::EXEC_RUN, &m::ExecRunParams {
                sandbox_id: self.sandbox_id.as_str().to_owned(),
                spec:       m::ExecSpecDto::from_spec(spec),
            })
            .await?;
        result.into_result()
    }

    async fn run_streaming(
        &self,
        spec: &ExecSpec,
        controls: ExecControls,
    ) -> Result<ExecStreamingResult> {
        let exec_id = format!(
            "x{}-{}",
            self.sandbox_id.as_str(),
            self.client.next_exec.fetch_add(1, Ordering::Relaxed)
        );
        // The caller's sink runs in a pump task fed by a per-exec ordered
        // queue, never in the shared reader task.
        let pump = controls.sink.clone().map(|sink| {
            let (queue, mut receiver) = mpsc::channel::<ExecChunk>(EXEC_STREAM_QUEUE);
            self.client
                .exec_streams
                .lock()
                .expect("exec streams lock")
                .insert(exec_id.clone(), queue);
            tokio::spawn(async move {
                while let Some((stream, chunk)) = receiver.recv().await {
                    let _ = sink(stream, chunk).await;
                }
            })
        });
        // Forward cancellation as an exec/cancel request.
        let cancel_task = controls.cancel.clone().map(|token| {
            let client = Arc::clone(&self.client);
            let exec_id = exec_id.clone();
            tokio::spawn(async move {
                token.cancelled().await;
                let _: Result<m::Empty> = client
                    .call(m::EXEC_CANCEL, &m::ExecCancelParams { exec_id })
                    .await;
            })
        });

        let outcome: Result<m::ExecStreamResult> = self
            .client
            .call(m::EXEC_STREAM, &m::ExecStreamParams {
                sandbox_id:            self.sandbox_id.as_str().to_owned(),
                exec_id:               exec_id.clone(),
                spec:                  m::ExecSpecDto::from_spec(spec),
                retained_output_limit: controls.retained_output_limit,
            })
            .await;

        self.client
            .exec_streams
            .lock()
            .expect("exec streams lock")
            .remove(&exec_id);
        if let Some(pump) = pump {
            // The queue sender is gone; the pump drains what remains and
            // ends, so every chunk is delivered before the result is.
            let _ = pump.await;
        }
        if let Some(task) = cancel_task {
            task.abort();
        }
        let result = outcome?;
        let mut streaming = ExecStreamingResult::new(result.result.into_result()?);
        streaming.streams_separated = result.streams_separated;
        streaming.live_streaming = result.live_streaming;
        streaming.stdout_capture = result.stdout_capture;
        streaming.stderr_capture = result.stderr_capture;
        Ok(streaming)
    }

    async fn spawn_stdio(&self, spec: &SpawnSpec) -> Result<StdioProcess> {
        let process_id = self.client.next_stream_id("stdio");
        let _: m::Empty = self
            .client
            .call(m::EXEC_STDIO_OPEN, &m::StdioOpenParams {
                sandbox_id: self.sandbox_id.as_str().to_owned(),
                process_id: process_id.clone(),
                spec:       spec.clone(),
            })
            .await?;

        let (stdin_writer, mut stdin_reader) = duplex(64 * 1024);
        let input_client = Arc::clone(&self.client);
        let input_id = process_id.clone();
        let input_task = tokio::spawn(async move {
            let mut buffer = vec![0; 32 * 1024];
            loop {
                let read = match stdin_reader.read(&mut buffer).await {
                    Ok(0) | Err(_) => break,
                    Ok(read) => read,
                };
                let outcome: Result<m::Empty> = input_client
                    .call(m::EXEC_STDIO_INPUT, &m::StdioInputParams {
                        process_id: input_id.clone(),
                        data_b64:   encode_bytes(&buffer[..read]),
                    })
                    .await;
                if outcome.is_err() {
                    return;
                }
            }
            let _: Result<m::Empty> = input_client
                .call(m::EXEC_STDIO_CLOSE_INPUT, &m::StdioIdParams {
                    process_id: input_id,
                })
                .await;
        });

        let (mut stdout_writer, stdout_reader) = duplex(64 * 1024);
        let output_client = Arc::clone(&self.client);
        let output_id = process_id.clone();
        let output_task = tokio::spawn(async move {
            loop {
                let result: Result<m::StdioOutputResult> = output_client
                    .call(m::EXEC_STDIO_OUTPUT, &m::StdioIdParams {
                        process_id: output_id.clone(),
                    })
                    .await;
                let Ok(result) = result else { break };
                let Some(chunk) = result.data_b64 else { break };
                let Ok(chunk) = decode_bytes(&chunk) else {
                    break;
                };
                if stdout_writer.write_all(&chunk).await.is_err() {
                    break;
                }
            }
            let _ = stdout_writer.shutdown().await;
        });

        let stderr_tail = StderrTail::default();
        let handle = RemoteStdioHandle {
            client: Arc::clone(&self.client),
            process_id,
            stderr_tail: stderr_tail.clone(),
            outcome: OnceCell::new(),
            input_task: AsyncMutex::new(Some(input_task)),
            output_task: AsyncMutex::new(Some(output_task)),
        };
        Ok(StdioProcess {
            stdin: Box::pin(stdin_writer),
            stdout: Box::pin(stdout_reader),
            stderr_tail,
            handle: Box::new(handle),
        })
    }
}

struct RemoteStdioHandle {
    client:      Arc<Client>,
    process_id:  String,
    stderr_tail: StderrTail,
    outcome:     OnceCell<(Termination, Option<i32>)>,
    input_task:  AsyncMutex<Option<JoinHandle<()>>>,
    output_task: AsyncMutex<Option<JoinHandle<()>>>,
}

#[async_trait]
impl StdioProcessHandle for RemoteStdioHandle {
    async fn terminate(&self) {
        let _: Result<m::Empty> = self
            .client
            .call(m::EXEC_STDIO_TERMINATE, &m::StdioIdParams {
                process_id: self.process_id.clone(),
            })
            .await;
    }

    async fn wait(&self) -> (Termination, Option<i32>) {
        *self
            .outcome
            .get_or_init(|| async {
                let result: Result<m::StdioWaitResult> = self
                    .client
                    .call(m::EXEC_STDIO_WAIT, &m::StdioIdParams {
                        process_id: self.process_id.clone(),
                    })
                    .await;
                let Ok(result) = result else {
                    return (Termination::Unknown, None);
                };
                self.stderr_tail.push(result.stderr_tail.as_bytes());
                if let Some(task) = self.output_task.lock().await.take() {
                    let _ = task.await;
                }
                if let Some(task) = self.input_task.lock().await.take() {
                    task.abort();
                }
                (result.termination, result.exit_code)
            })
            .await
    }
}

struct SandboxFs {
    client:     Arc<Client>,
    sandbox_id: SandboxId,
}

impl SandboxFs {
    fn path_params(&self, path: &str) -> m::FsPathParams {
        m::FsPathParams {
            sandbox_id: self.sandbox_id.as_str().to_owned(),
            path:       path.to_owned(),
        }
    }
}

#[async_trait]
impl Filesystem for SandboxFs {
    async fn read(&self, path: &str) -> Result<Vec<u8>> {
        let result: m::FsReadResult = self
            .client
            .call(m::FS_READ, &m::FsReadParams {
                sandbox_id: self.sandbox_id.as_str().to_owned(),
                path:       path.to_owned(),
                offset:     None,
                length:     None,
            })
            .await?;
        decode_bytes(&result.content_b64)
    }

    async fn read_range(&self, path: &str, offset: u64, length: Option<u64>) -> Result<Vec<u8>> {
        let result: m::FsReadResult = self
            .client
            .call(m::FS_READ, &m::FsReadParams {
                sandbox_id: self.sandbox_id.as_str().to_owned(),
                path: path.to_owned(),
                offset: Some(offset),
                length,
            })
            .await?;
        decode_bytes(&result.content_b64)
    }

    async fn write(&self, path: &str, content: &[u8]) -> Result<()> {
        let _: m::Empty = self
            .client
            .call(m::FS_WRITE, &m::FsWriteParams {
                sandbox_id:  self.sandbox_id.as_str().to_owned(),
                path:        path.to_owned(),
                content_b64: encode_bytes(content),
                append:      false,
            })
            .await?;
        Ok(())
    }

    async fn write_append(&self, path: &str, content: &[u8]) -> Result<()> {
        let _: m::Empty = self
            .client
            .call(m::FS_WRITE, &m::FsWriteParams {
                sandbox_id:  self.sandbox_id.as_str().to_owned(),
                path:        path.to_owned(),
                content_b64: encode_bytes(content),
                append:      true,
            })
            .await?;
        Ok(())
    }

    async fn delete(&self, path: &str, recursive: bool) -> Result<()> {
        let _: m::Empty = self
            .client
            .call(m::FS_DELETE, &m::FsDeleteParams {
                sandbox_id: self.sandbox_id.as_str().to_owned(),
                path: path.to_owned(),
                recursive,
            })
            .await?;
        Ok(())
    }

    async fn exists(&self, path: &str) -> Result<bool> {
        let result: m::FsExistsResult = self
            .client
            .call(m::FS_EXISTS, &self.path_params(path))
            .await?;
        Ok(result.exists)
    }

    async fn metadata(&self, path: &str) -> Result<FileMetadata> {
        let result: m::FsMetadataResult = self
            .client
            .call(m::FS_METADATA, &self.path_params(path))
            .await?;
        Ok(result.metadata)
    }

    async fn list_dir(&self, path: &str, depth: usize) -> Result<Vec<DirEntry>> {
        let result: m::FsListDirResult = self
            .client
            .call(m::FS_LIST_DIR, &m::FsListDirParams {
                sandbox_id: self.sandbox_id.as_str().to_owned(),
                path: path.to_owned(),
                depth,
            })
            .await?;
        Ok(result.entries)
    }

    async fn create_dir(&self, path: &str) -> Result<()> {
        let _: m::Empty = self
            .client
            .call(m::FS_CREATE_DIR, &self.path_params(path))
            .await?;
        Ok(())
    }

    async fn rename(&self, from: &str, to: &str) -> Result<()> {
        let _: m::Empty = self
            .client
            .call(m::FS_RENAME, &m::FsRenameParams {
                sandbox_id: self.sandbox_id.as_str().to_owned(),
                from:       from.to_owned(),
                to:         to.to_owned(),
            })
            .await?;
        Ok(())
    }

    async fn set_permissions(&self, path: &str, mode: u32) -> Result<()> {
        let _: m::Empty = self
            .client
            .call(m::FS_SET_PERMISSIONS, &m::FsSetPermissionsParams {
                sandbox_id: self.sandbox_id.as_str().to_owned(),
                path: path.to_owned(),
                mode,
            })
            .await?;
        Ok(())
    }

    async fn upload(&self, local: &Path, remote: &str) -> Result<()> {
        // Bounded chunks: a large file must never become one NDJSON line
        // buffered whole on both sides of the pipe.
        let mut file = tokio_fs::File::open(local)
            .await
            .map_err(|error| Error::io(format!("reading {}", local.display()), error))?;
        let mut first = true;
        loop {
            let mut chunk = Vec::with_capacity(TRANSFER_CHUNK_BYTES);
            let read = (&mut file)
                .take(TRANSFER_CHUNK_BYTES as u64)
                .read_to_end(&mut chunk)
                .await
                .map_err(|error| Error::io(format!("reading {}", local.display()), error))?;
            if first {
                // The first chunk truncates and creates parents; an
                // empty file is one empty write.
                self.write(remote, &chunk).await?;
                first = false;
            } else if read > 0 {
                self.write_append(remote, &chunk).await?;
            }
            if read < TRANSFER_CHUNK_BYTES {
                return Ok(());
            }
        }
    }

    async fn download(&self, remote: &str, local: &Path) -> Result<()> {
        if let Some(parent) = local.parent() {
            tokio_fs::create_dir_all(parent).await.map_err(|error| {
                Error::io(format!("creating parent of {}", local.display()), error)
            })?;
        }
        let mut file = tokio_fs::File::create(local)
            .await
            .map_err(|error| Error::io(format!("writing {}", local.display()), error))?;
        let mut offset: u64 = 0;
        loop {
            let chunk = self
                .read_range(remote, offset, Some(TRANSFER_CHUNK_BYTES as u64))
                .await?;
            file.write_all(&chunk)
                .await
                .map_err(|error| Error::io(format!("writing {}", local.display()), error))?;
            offset += chunk.len() as u64;
            if chunk.len() < TRANSFER_CHUNK_BYTES {
                break;
            }
        }
        file.flush()
            .await
            .map_err(|error| Error::io(format!("writing {}", local.display()), error))
    }
}
