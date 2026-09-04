//! Host-side client: adapts a JSON-RPC plugin back into the
//! [`SandboxProvider`] / [`Sandbox`] traits.
//!
//! Control requests and responses cross the plugin's stdio; every byte
//! stream rides a data channel the plugin opens back to this host
//! ([`crate::channel`]). Each operation that moves bytes registers the
//! channel it expects before it sends the request, pumps it concurrently
//! with awaiting the response, and returns only after the channel ends —
//! so a result never arrives ahead of the output it describes.

use std::collections::{BTreeMap, HashMap};
use std::path::Path;
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use sandbox_driver::{
    Capabilities, Capability, DirEntry, Error, EventContext, EventSubject, Exec, ExecControls,
    ExecResult, ExecSpec, ExecStreamingResult, FileMetadata, Filesystem, ForkOptions, HealthStatus,
    LifecycleTimers, LogSink, LogSource, Logs, NetworkPolicy, OneShot, OneShotSpec,
    OutputCaptureBuffer, OutputSink, OutputStream, PlatformInfo, PreviewUrl, PreviewUrls,
    ProviderHealth, ProviderKind, Pty, PtyOptions, PtySession, PtySize, Resources, Result, Sandbox,
    SandboxFilter, SandboxId, SandboxSnapshotOptions, SandboxSpec, SandboxStatus, SnapshotFilter,
    SnapshotId, SnapshotProvider, SnapshotSpec, SnapshotStatus, SpawnSpec, SshAccess,
    SshAccessInfo, StderrTail, StdinReader, StdioProcess, StdioProcessHandle, StopLevel,
    Termination, TransportError, Vnc, VncConnection, VolumeId, VolumeProvider, VolumeSpec,
    VolumeStatus, WebTerminal,
};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;
use tokio::io::{
    AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, duplex,
};
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::process::{Child, Command};
use tokio::runtime::Handle as RuntimeHandle;
use tokio::sync::{Mutex as AsyncMutex, OnceCell, mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio::{fs as tokio_fs, time};
use tracing::field;

use crate::channel::{
    Channel, ChannelListener, ChannelReceiver, FrameKind, FrameReader, FrameWriter,
};
use crate::methods as m;
use crate::wire::Message;

/// How long the host waits, after a plugin has answered an operation,
/// for the data channel that operation must already have opened.
const LATE_CHANNEL_GRACE: Duration = Duration::from_secs(10);

/// A provider served by a JSON-RPC plugin over a byte stream.
///
/// `connect` binds the data transport, performs the `initialize`
/// handshake, and returns a provider whose capabilities are the plugin's
/// declared set. The background read and write tasks end when the
/// transport closes or the provider is dropped.
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
    #[tracing::instrument(skip_all, err)]
    pub async fn connect(
        reader: impl AsyncRead + Unpin + Send + 'static,
        writer: impl AsyncWrite + Unpin + Send + 'static,
    ) -> Result<Self> {
        let listener = ChannelListener::bind()?;
        let transport = listener.transport();
        let client = Client::start(reader, writer, listener);
        let result: m::InitializeResult = client
            .call(m::INITIALIZE, &m::InitializeParams {
                protocol_version: m::PROTOCOL_VERSION,
                data_transport:   transport,
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
    #[tracing::instrument(skip_all, err)]
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

    /// Whether the control transport is still open. `false` once the
    /// plugin exited or its stdio broke; every later call fails at once.
    pub fn is_closed(&self) -> bool {
        self.client.closed.load(Ordering::SeqCst)
    }

    /// Asks the plugin to shut down cleanly and, for a spawned plugin,
    /// reaps the child — killing it after a grace period if it lingers.
    #[tracing::instrument(skip_all, fields(provider_kind = %self.kind), err)]
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
                tracing::warn!(provider_kind = %self.kind, "plugin did not exit after shutdown");
                if let Err(error) = child.kill().await {
                    tracing::warn!(
                        provider_kind = %self.kind,
                        error = ?error,
                        "plugin process kill failed"
                    );
                }
                child
                    .wait()
                    .await
                    .map_err(|error| Error::io("reaping plugin process", error))?;
            }
        }
        Ok(())
    }

    fn wrap_handle(
        &self,
        mut info: m::HandleInfo,
        events: Option<EventContext>,
    ) -> Arc<dyn Sandbox> {
        mask_wire_capabilities(&mut info.capabilities);
        let id = info.status.id.clone();
        if let Some(context) = &events {
            self.client
                .event_contexts
                .lock()
                .expect("event contexts lock")
                .insert(id.as_str().to_owned(), context.clone());
        }
        Arc::new(SandboxHandle::new(
            Arc::clone(&self.client),
            id,
            info.capabilities,
            info.working_directory,
            info.runtime_directory,
            events,
        ))
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
        events: Option<EventContext>,
    ) -> Result<Arc<dyn Sandbox>> {
        let event_request = self.client.register_events(events.as_ref());
        let outcome: Result<m::HandleInfo> = self
            .client
            .call(m::SANDBOX_CREATE, &m::CreateParams {
                spec:   m::SandboxSpecDto::try_from(spec)?,
                events: event_request.clone(),
            })
            .await;
        self.client.unregister_events(event_request.as_ref());
        Ok(self.wrap_handle(outcome?, events))
    }

    async fn attach(
        &self,
        id: &SandboxId,
        events: Option<EventContext>,
    ) -> Result<Arc<dyn Sandbox>> {
        let event_request = self.client.register_events(events.as_ref());
        let outcome: Result<m::HandleInfo> = self
            .client
            .call(m::SANDBOX_ATTACH, &m::AttachParams {
                sandbox_id: id.as_str().to_owned(),
                events:     event_request.clone(),
            })
            .await;
        self.client.unregister_events(event_request.as_ref());
        Ok(self.wrap_handle(outcome?, events))
    }

    async fn undelete(
        &self,
        id: &SandboxId,
        events: Option<EventContext>,
    ) -> Result<Arc<dyn Sandbox>> {
        let event_request = self.client.register_events(events.as_ref());
        let outcome: Result<m::HandleInfo> = self
            .client
            .call(m::SANDBOX_UNDELETE, &m::AttachParams {
                sandbox_id: id.as_str().to_owned(),
                events:     event_request.clone(),
            })
            .await;
        self.client.unregister_events(event_request.as_ref());
        Ok(self.wrap_handle(outcome?, events))
    }

    async fn delete(&self, id: &SandboxId, events: Option<EventContext>) -> Result<()> {
        let event_request = self.client.register_events(events.as_ref());
        let outcome: Result<m::Empty> = self
            .client
            .call(m::SANDBOX_DELETE, &m::AttachParams {
                sandbox_id: id.as_str().to_owned(),
                events:     event_request.clone(),
            })
            .await;
        self.client.unregister_events(event_request.as_ref());
        outcome.map(|_| ())
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
            // A plugin without provider/health answers -32601; that is
            // "no health check", not a failed one.
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
    async fn create(
        &self,
        spec: &SnapshotSpec,
        events: Option<EventContext>,
    ) -> Result<SnapshotId> {
        let event_request = self.client.register_events(events.as_ref());
        let outcome: Result<m::SnapshotIdResult> = self
            .client
            .call(m::SNAPSHOT_CREATE, &m::SnapshotCreateParams {
                spec:   m::SnapshotSpecDto::try_from(spec)?,
                events: event_request.clone(),
            })
            .await;
        self.client.unregister_events(event_request.as_ref());
        let result = outcome?;
        SnapshotId::try_new(result.snapshot_id)
            .map_err(|error| Error::invalid_spec("snapshot_id", error.to_string()))
    }

    async fn get(&self, id: &SnapshotId) -> Result<SnapshotStatus> {
        let result: m::SnapshotStatusResult = self
            .client
            .call(m::SNAPSHOT_GET, &m::SnapshotIdParams {
                snapshot_id: id.as_str().to_owned(),
                events:      None,
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

    async fn delete(&self, id: &SnapshotId, events: Option<EventContext>) -> Result<()> {
        let event_request = self.client.register_events(events.as_ref());
        let outcome: Result<m::Empty> = self
            .client
            .call(m::SNAPSHOT_DELETE, &m::SnapshotIdParams {
                snapshot_id: id.as_str().to_owned(),
                events:      event_request.clone(),
            })
            .await;
        self.client.unregister_events(event_request.as_ref());
        outcome?;
        Ok(())
    }

    async fn build_logs(&self, id: &SnapshotId, follow: bool, sink: LogSink) -> Result<()> {
        let stream_id = self.client.next_stream_id("snapshot");
        let (channel, receiver) = self.client.listener.expect();
        follow_log_stream(
            &self.client,
            m::SNAPSHOT_BUILD_LOGS,
            &m::SnapshotBuildLogsParams {
                snapshot_id: id.as_str().to_owned(),
                stream_id: stream_id.clone(),
                channel,
                follow,
            },
            &stream_id,
            receiver,
            sink,
        )
        .await
    }

    async fn activate(&self, id: &SnapshotId, events: Option<EventContext>) -> Result<()> {
        let event_request = self.client.register_events(events.as_ref());
        let outcome: Result<m::Empty> = self
            .client
            .call(m::SNAPSHOT_ACTIVATE, &m::SnapshotIdParams {
                snapshot_id: id.as_str().to_owned(),
                events:      event_request.clone(),
            })
            .await;
        self.client.unregister_events(event_request.as_ref());
        outcome?;
        Ok(())
    }

    async fn deactivate(&self, id: &SnapshotId, events: Option<EventContext>) -> Result<()> {
        let event_request = self.client.register_events(events.as_ref());
        let outcome: Result<m::Empty> = self
            .client
            .call(m::SNAPSHOT_DEACTIVATE, &m::SnapshotIdParams {
                snapshot_id: id.as_str().to_owned(),
                events:      event_request.clone(),
            })
            .await;
        self.client.unregister_events(event_request.as_ref());
        outcome?;
        Ok(())
    }
}

/// Volume service backed by the plugin.
struct ProviderVolumes {
    client: Arc<Client>,
}

#[async_trait]
impl VolumeProvider for ProviderVolumes {
    async fn create(&self, spec: &VolumeSpec, events: Option<EventContext>) -> Result<VolumeId> {
        let event_request = self.client.register_events(events.as_ref());
        let outcome: Result<m::VolumeIdResult> = self
            .client
            .call(m::VOLUME_CREATE, &m::VolumeCreateParams {
                spec:   spec.clone(),
                events: event_request.clone(),
            })
            .await;
        self.client.unregister_events(event_request.as_ref());
        let result = outcome?;
        VolumeId::try_new(result.volume_id)
            .map_err(|error| Error::invalid_spec("volume_id", error.to_string()))
    }

    async fn get(&self, id: &VolumeId) -> Result<VolumeStatus> {
        let result: m::VolumeStatusResult = self
            .client
            .call(m::VOLUME_GET, &m::VolumeIdParams {
                volume_id: id.as_str().to_owned(),
                events:    None,
            })
            .await?;
        Ok(result.status)
    }

    async fn list(&self) -> Result<Vec<VolumeStatus>> {
        let result: m::VolumeListResult = self.client.call(m::VOLUME_LIST, &m::Empty).await?;
        Ok(result.volumes)
    }

    async fn delete(&self, id: &VolumeId, events: Option<EventContext>) -> Result<()> {
        let event_request = self.client.register_events(events.as_ref());
        let outcome: Result<m::Empty> = self
            .client
            .call(m::VOLUME_DELETE, &m::VolumeIdParams {
                volume_id: id.as_str().to_owned(),
                events:    event_request.clone(),
            })
            .await;
        self.client.unregister_events(event_request.as_ref());
        outcome?;
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
    async fn ssh_access(&self, ttl: Option<Duration>) -> Result<SshAccessInfo> {
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
/// process-local; everything else, streamed stdin and the effective
/// environment included, crosses in version 2.
fn mask_wire_capabilities(capabilities: &mut Capabilities) {
    capabilities.search.native = false;
    capabilities.git.native = false;
    capabilities.services.native = false;
    capabilities.access.shell_command = false;
}

/// Request/response correlation plus notification routing.
///
/// The reader task never awaits consumer code: it only resolves pending
/// calls and forwards events. Every byte stream has a connection of its
/// own, pumped by the operation that asked for it.
struct Client {
    outbound:       mpsc::Sender<Message>,
    listener:       ChannelListener,
    next_id:        AtomicU64,
    next_exec:      AtomicU64,
    next_stream:    AtomicU64,
    next_operation: AtomicU64,
    /// Set when either transport task ends; every pending and future call
    /// fails fast instead of waiting on a dead pipe.
    closed:         AtomicBool,
    closed_error:   Mutex<Option<TransportError>>,
    pending:        Mutex<HashMap<u64, oneshot::Sender<Result<Value>>>>,
    event_contexts: Mutex<HashMap<String, EventContext>>,
    /// Contexts for in-flight resource operations, keyed by a wire-only
    /// route id so events can arrive before a resource id exists.
    event_routes:   Mutex<HashMap<String, EventContext>>,
}

impl Client {
    fn start(
        reader: impl AsyncRead + Unpin + Send + 'static,
        writer: impl AsyncWrite + Unpin + Send + 'static,
        listener: ChannelListener,
    ) -> Arc<Self> {
        let (outbound, mut outbound_rx) = mpsc::channel::<Message>(256);
        let client = Arc::new(Self {
            outbound,
            listener,
            next_id: AtomicU64::new(1),
            next_exec: AtomicU64::new(1),
            next_stream: AtomicU64::new(1),
            next_operation: AtomicU64::new(1),
            closed: AtomicBool::new(false),
            closed_error: Mutex::new(None),
            pending: Mutex::new(HashMap::new()),
            event_contexts: Mutex::new(HashMap::new()),
            event_routes: Mutex::new(HashMap::new()),
        });

        let writer_client = Arc::clone(&client);
        tokio::spawn(async move {
            let mut writer = writer;
            let outcome: Result<(), TransportError> = async {
                while let Some(message) = outbound_rx.recv().await {
                    let mut line = serde_json::to_string(&message).map_err(|error| {
                        TransportError::with_source("serializing plugin request", error)
                    })?;
                    line.push('\n');
                    writer.write_all(line.as_bytes()).await.map_err(|error| {
                        TransportError::with_source("writing plugin request", error)
                    })?;
                }
                writer.shutdown().await.map_err(|error| {
                    TransportError::with_source("shutting down plugin writer", error)
                })?;
                Ok(())
            }
            .await;
            writer_client.mark_closed(
                outcome
                    .err()
                    .unwrap_or_else(|| TransportError::new("plugin request transport closed")),
            );
        });

        let reader_client = Arc::clone(&client);
        tokio::spawn(async move {
            let mut lines = BufReader::new(reader).lines();
            let outcome: Result<(), TransportError> = async {
                loop {
                    let Some(line) = lines.next_line().await.map_err(|error| {
                        TransportError::with_source("reading plugin response", error)
                    })?
                    else {
                        return Ok(());
                    };
                    if line.trim().is_empty() {
                        continue;
                    }
                    let message = serde_json::from_str::<Message>(&line).map_err(|error| {
                        TransportError::with_source("decoding plugin response", error)
                    })?;
                    reader_client.route(message).await?;
                }
            }
            .await;
            reader_client.mark_closed(
                outcome
                    .err()
                    .unwrap_or_else(|| TransportError::new("plugin response transport closed")),
            );
        });

        client
    }

    /// Marks the transport dead and fails everything pending. Called by
    /// both transport tasks; also re-checked by `call` after registering,
    /// closing the race where a call lands just after the drain.
    fn mark_closed(&self, error: TransportError) {
        let first_failure = !self.closed.swap(true, Ordering::SeqCst);
        let error = {
            let mut closed_error = self.closed_error.lock().expect("closed error lock");
            closed_error.get_or_insert(error).clone()
        };
        if first_failure {
            tracing::error!(error = ?error, "plugin transport failed");
        }
        let pending: Vec<_> = {
            let mut pending = self.pending.lock().expect("pending lock");
            pending.drain().collect()
        };
        for (_, sender) in pending {
            let _ = sender.send(Err(Error::Transport(error.clone())));
        }
        self.event_contexts
            .lock()
            .expect("event contexts lock")
            .clear();
        self.event_routes.lock().expect("event routes lock").clear();
    }

    fn closed_error(&self) -> Error {
        let error = self
            .closed_error
            .lock()
            .expect("closed error lock")
            .clone()
            .unwrap_or_else(|| TransportError::new("plugin transport closed"));
        Error::Transport(error)
    }

    fn next_stream_id(&self, prefix: &str) -> String {
        format!(
            "{prefix}-{}",
            self.next_stream.fetch_add(1, Ordering::Relaxed)
        )
    }

    fn next_exec_id(&self, sandbox_id: &SandboxId) -> String {
        format!(
            "x{}-{}",
            sandbox_id.as_str(),
            self.next_exec.fetch_add(1, Ordering::Relaxed)
        )
    }

    fn register_events(&self, events: Option<&EventContext>) -> Option<m::EventRequest> {
        events.map(|context| {
            let route_id = format!(
                "event-{}",
                self.next_operation.fetch_add(1, Ordering::Relaxed)
            );
            self.event_routes
                .lock()
                .expect("event routes lock")
                .insert(route_id.clone(), context.clone());
            m::EventRequest {
                route_id,
                correlation_id: context.correlation_id_ref().cloned(),
            }
        })
    }

    fn unregister_events(&self, request: Option<&m::EventRequest>) {
        if let Some(request) = request {
            self.event_routes
                .lock()
                .expect("event routes lock")
                .remove(&request.route_id);
        }
    }

    async fn route(&self, message: Message) -> Result<(), TransportError> {
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
            return Ok(());
        }
        let Some(method) = message.method.as_deref() else {
            return Ok(());
        };
        let params = message.params.unwrap_or(Value::Null);
        if method == m::HOST_EVENT {
            let notification =
                serde_json::from_value::<m::HostEventNotification>(params).map_err(|error| {
                    TransportError::with_source("decoding plugin host event", error)
                })?;
            // Route id first: a create event can arrive before a resource
            // id exists. Established sandbox handles fall back to the
            // resource id in the event subject.
            let resource_id = match &notification.event.subject {
                EventSubject::Sandbox { id: Some(id), .. } => Some(id.as_str()),
                _ => None,
            };
            let context = notification
                .route_id
                .as_ref()
                .and_then(|route_id| {
                    self.event_routes
                        .lock()
                        .expect("event routes lock")
                        .get(route_id)
                        .cloned()
                })
                .or_else(|| {
                    resource_id.and_then(|resource_id| {
                        self.event_contexts
                            .lock()
                            .expect("event contexts lock")
                            .get(resource_id)
                            .cloned()
                    })
                });
            if let Some(context) = context {
                context.forward(notification.event).await;
            }
        }
        Ok(())
    }

    #[tracing::instrument(
        skip_all,
        fields(method = method, request_id = field::Empty),
        err
    )]
    async fn call<P: Serialize, R: DeserializeOwned>(&self, method: &str, params: &P) -> Result<R> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        tracing::Span::current().record("request_id", id);
        let params = serde_json::to_value(params).map_err(|error| {
            Error::Transport(TransportError::with_source(
                "encoding plugin request parameters",
                error,
            ))
        })?;
        let (sender, receiver) = oneshot::channel();
        self.pending
            .lock()
            .expect("pending lock")
            .insert(id, sender);
        if self.closed.load(Ordering::SeqCst) {
            // The transport may have died between the drain and our
            // registration; drain again so this call cannot hang.
            self.pending.lock().expect("pending lock").remove(&id);
            return Err(self.closed_error());
        }
        if let Err(send_error) = self
            .outbound
            .send(Message::request(id, method, params))
            .await
        {
            self.pending.lock().expect("pending lock").remove(&id);
            return Err(Error::Transport(TransportError::with_source(
                "sending plugin request",
                send_error,
            )));
        }
        let value = receiver.await.map_err(|error| {
            Error::Transport(TransportError::with_source(
                "receiving plugin response",
                error,
            ))
        })??;
        serde_json::from_value(value).map_err(|error| {
            Error::Transport(TransportError::with_source(
                "decoding plugin response result",
                error,
            ))
        })
    }

    /// Fires an `exec/stop` for each stop token as it fires: a term then
    /// a kill are two requests, in that order.
    fn forward_stops(
        self: &Arc<Self>,
        exec_id: &str,
        controls: &ExecControls,
    ) -> Option<JoinHandle<()>> {
        (controls.term.is_some() || controls.kill.is_some()).then(|| {
            let client = Arc::clone(self);
            let exec_id = exec_id.to_owned();
            let term = controls.term.clone();
            let kill = controls.kill.clone();
            tokio::spawn(async move {
                let mut termed = std::pin::pin!(sandbox_driver::stop_signal(term.as_ref()));
                let mut killed = std::pin::pin!(sandbox_driver::stop_signal(kill.as_ref()));
                let mut term_sent = false;
                loop {
                    let level = tokio::select! {
                        () = &mut termed, if !term_sent => StopLevel::Term,
                        () = &mut killed => StopLevel::Kill,
                    };
                    client.send_stop(&exec_id, level).await;
                    if level == StopLevel::Kill {
                        break;
                    }
                    term_sent = true;
                }
            })
        })
    }

    async fn send_stop(&self, exec_id: &str, level: StopLevel) {
        let outcome: Result<m::Empty> = self
            .call(m::EXEC_STOP, &m::ExecStopParams {
                exec_id: exec_id.to_owned(),
                level,
            })
            .await;
        if let Err(error) = outcome {
            tracing::warn!(error = %error, ?level, "plugin exec stop failed");
        }
    }
}

/// Waits for a task that was pumping a data channel, after the operation
/// it belongs to has answered. The plugin ends the channel before it
/// answers, so a channel that never even opened is a broken plugin, not
/// slow output.
async fn join_pump<T>(pump: JoinHandle<Result<T>>, accepted: &AtomicBool, what: &str) -> Result<T> {
    let joined = if accepted.load(Ordering::SeqCst) {
        pump.await
    } else {
        match time::timeout(LATE_CHANNEL_GRACE, pump).await {
            Ok(joined) => joined,
            Err(_) => {
                return Err(Error::Transport(TransportError::new(format!(
                    "the plugin answered {what} without opening its data channel"
                ))));
            }
        }
    };
    joined.map_err(|error| {
        Error::Transport(TransportError::with_source(
            "joining a data channel pump",
            error,
        ))
    })?
}

/// What an exec pump collected while the command ran.
struct PumpedOutput {
    stdout:     OutputCaptureBuffer,
    stderr:     OutputCaptureBuffer,
    /// The caller's sink failed on this chunk: the command was killed and
    /// the result reports a cancellation.
    sink_error: Option<Error>,
}

/// Pumps one exec's channel: output frames go to the capture buffers and
/// the caller's sink, stdin bytes go out as frames. Ends when the plugin
/// sends its `Eof`.
async fn pump_exec_channel(
    client: Arc<Client>,
    exec_id: String,
    receiver: ChannelReceiver,
    accepted: Arc<AtomicBool>,
    stdin: Option<StdinReader>,
    sink: Option<OutputSink>,
    retained_output_limit: Option<usize>,
) -> Result<PumpedOutput> {
    let Channel { mut reader, writer } = receiver.accept().await?;
    accepted.store(true, Ordering::SeqCst);
    let mut writer = Some(writer);
    let stdin_task = stdin.map(|reader| {
        let writer = writer.take().expect("the writer is handed to stdin once");
        tokio::spawn(feed_stdin_frames(reader, writer))
    });
    let mut output = PumpedOutput {
        stdout:     OutputCaptureBuffer::new(retained_output_limit),
        stderr:     OutputCaptureBuffer::new(retained_output_limit),
        sink_error: None,
    };
    loop {
        let frame = match reader.read().await {
            Ok(Some(frame)) => frame,
            Ok(None) => break,
            Err(error) => {
                if let Some(task) = stdin_task {
                    task.abort();
                }
                return Err(error);
            }
        };
        let (stream, payload) = match frame {
            (FrameKind::Stdout, payload) => (OutputStream::Stdout, payload),
            (FrameKind::Stderr, payload) => (OutputStream::Stderr, payload),
            (FrameKind::Eof, _) => break,
            (kind, _) => {
                tracing::warn!(?kind, "unexpected frame on an exec channel");
                continue;
            }
        };
        match stream {
            OutputStream::Stdout => output.stdout.push(&payload),
            OutputStream::Stderr => output.stderr.push(&payload),
        }
        if output.sink_error.is_some() || payload.is_empty() {
            continue;
        }
        if let Some(sink) = &sink {
            if let Err(error) = sink(stream, payload).await {
                // A failing sink is a hard stop on every provider; the
                // rest of the stream is drained and dropped.
                client.send_stop(&exec_id, StopLevel::Kill).await;
                output.sink_error = Some(error);
            }
        }
    }
    if let Some(task) = stdin_task {
        // The command is done; unwritten stdin bytes are unwanted.
        task.abort();
    }
    Ok(output)
}

/// Copies `reader` into the channel as `Stdin` frames, then sends the
/// host's `Eof`. A channel the plugin closed is the command declining
/// its input, which is not an error.
async fn feed_stdin_frames(mut reader: StdinReader, mut writer: FrameWriter<OwnedWriteHalf>) {
    let mut buffer = vec![0; 32 * 1024];
    loop {
        match reader.read(&mut buffer).await {
            Ok(0) => break,
            Err(error) => {
                tracing::debug!(error = %error, "exec stdin source failed");
                break;
            }
            Ok(read) => {
                if writer
                    .write(FrameKind::Stdin, &buffer[..read])
                    .await
                    .is_err()
                {
                    return;
                }
            }
        }
    }
    let _ = writer.finish().await;
}

/// Runs a channel-backed command to its result: sends the request, pumps
/// the channel, forwards stops, and assembles the result from the host's
/// retained copy plus the plugin's metadata.
async fn run_channel_exec<P: Serialize>(
    client: &Arc<Client>,
    method: &str,
    params: &P,
    exec_id: &str,
    receiver: ChannelReceiver,
    stdin: Option<StdinReader>,
    controls: &ExecControls,
) -> Result<ExecStreamingResult> {
    let accepted = Arc::new(AtomicBool::new(false));
    let pump = tokio::spawn(pump_exec_channel(
        Arc::clone(client),
        exec_id.to_owned(),
        receiver,
        Arc::clone(&accepted),
        stdin,
        controls.sink.clone(),
        controls.retained_output_limit,
    ));
    let stop_task = client.forward_stops(exec_id, controls);
    let outcome: Result<m::ExecStreamResult> = client.call(method, params).await;
    if let Some(task) = stop_task {
        task.abort();
    }
    let result = match outcome {
        Ok(result) => result,
        Err(error) => {
            pump.abort();
            return Err(error);
        }
    };
    let pumped = join_pump(pump, &accepted, method).await?;
    let (stdout, mut stdout_stats) = pumped.stdout.into_parts();
    let (stderr, mut stderr_stats) = pumped.stderr.into_parts();
    stdout_stats.truncated = result.stdout_capture.truncated;
    stderr_stats.truncated = result.stderr_capture.truncated;
    let mut exec_result = result.result.into_result(stdout, stderr);
    if pumped.sink_error.is_some() {
        exec_result.termination = Termination::Cancelled;
    }
    let mut streaming = ExecStreamingResult::new(exec_result);
    streaming.streams_separated = result.streams_separated;
    streaming.live_streaming = result.live_streaming;
    streaming.stdout_capture = stdout_stats;
    streaming.stderr_capture = stderr_stats;
    Ok(streaming)
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
                let outcome: Result<m::Empty> = client
                    .call(m::STREAM_CANCEL, &m::StreamIdParams { stream_id })
                    .await;
                if let Err(error) = outcome {
                    tracing::warn!(error = %error, "plugin log stream cancellation failed");
                }
            });
        } else {
            tracing::debug!("plugin log stream cancellation skipped without a runtime");
        }
    }
}

/// Feeds a log channel to `sink` until the plugin's `Eof`. A sink error
/// ends the pump and is the caller's result.
async fn pump_log_channel(
    receiver: ChannelReceiver,
    accepted: Arc<AtomicBool>,
    sink: LogSink,
) -> Result<()> {
    let Channel { mut reader, .. } = receiver.accept().await?;
    accepted.store(true, Ordering::SeqCst);
    loop {
        match reader.read().await? {
            Some((FrameKind::Stdout | FrameKind::Stderr, payload)) => sink(payload).await?,
            Some((FrameKind::Eof, _)) | None => return Ok(()),
            Some((kind, _)) => tracing::warn!(?kind, "unexpected frame on a log channel"),
        }
    }
}

async fn follow_log_stream<P: Serialize>(
    client: &Arc<Client>,
    method: &str,
    params: &P,
    stream_id: &str,
    receiver: ChannelReceiver,
    sink: LogSink,
) -> Result<()> {
    let mut guard = StreamCancelGuard {
        client:    Arc::clone(client),
        stream_id: stream_id.to_owned(),
        armed:     true,
    };
    let accepted = Arc::new(AtomicBool::new(false));
    let mut pump = tokio::spawn(pump_log_channel(receiver, Arc::clone(&accepted), sink));
    let mut call = Box::pin(client.call::<_, m::Empty>(method, params));
    let mut pumped: Option<Result<()>> = None;
    let outcome = loop {
        tokio::select! {
            outcome = &mut call => break outcome.map(|_| ()),
            joined = &mut pump, if pumped.is_none() => {
                let result = joined.map_err(|error| {
                    Error::Transport(TransportError::with_source(
                        "joining the log channel pump",
                        error,
                    ))
                });
                // A sink that refused a chunk ends the follow: the guard
                // cancels the stream and the error is the outcome.
                result.and_then(|result| result)?;
                pumped = Some(Ok(()));
            }
        }
    };
    guard.armed = false;
    match outcome {
        Ok(()) => {
            if pumped.is_none() {
                join_pump(pump, &accepted, method).await?;
            }
            Ok(())
        }
        Err(error) => {
            pump.abort();
            Err(error)
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
    one_shot:          SandboxOneShot,
    access:            SandboxAccess,
    pty:               SandboxPty,
    logs:              SandboxLogs,
    fs:                SandboxFs,
    events:            Option<EventContext>,
}

impl SandboxHandle {
    fn new(
        client: Arc<Client>,
        id: SandboxId,
        capabilities: Capabilities,
        working_directory: String,
        runtime_directory: Option<String>,
        events: Option<EventContext>,
    ) -> Self {
        Self {
            exec: SandboxExec {
                client:     Arc::clone(&client),
                sandbox_id: id.clone(),
            },
            one_shot: SandboxOneShot {
                client:     Arc::clone(&client),
                sandbox_id: id.clone(),
            },
            access: SandboxAccess {
                client:     Arc::clone(&client),
                sandbox_id: id.clone(),
            },
            pty: SandboxPty {
                client:     Arc::clone(&client),
                sandbox_id: id.clone(),
            },
            logs: SandboxLogs {
                client:     Arc::clone(&client),
                sandbox_id: id.clone(),
            },
            fs: SandboxFs {
                client:     Arc::clone(&client),
                sandbox_id: id.clone(),
            },
            client,
            id,
            capabilities,
            working_directory,
            runtime_directory,
            events,
        }
    }

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

    async fn environment(&self) -> Result<BTreeMap<String, String>> {
        if !self.capabilities.exec.environment {
            return Err(Error::unsupported(Capability::ExecEnvironment));
        }
        let result: m::EnvironmentResult = self
            .client
            .call(m::SANDBOX_ENVIRONMENT, &self.id_params())
            .await?;
        Ok(result.environment)
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
                options:    options.into(),
            })
            .await?;
        let id = info.status.id.clone();
        if let Some(context) = &self.events {
            self.client
                .event_contexts
                .lock()
                .expect("event contexts lock")
                .insert(id.as_str().to_owned(), context.clone());
        }
        Ok(Arc::new(Self::new(
            Arc::clone(&self.client),
            id,
            info.capabilities,
            info.working_directory,
            info.runtime_directory,
            self.events.clone(),
        )))
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
                options:    options.into(),
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

    fn one_shot(&self) -> Option<&dyn OneShot> {
        self.capabilities
            .one_shot
            .as_ref()
            .map(|_| &self.one_shot as &dyn OneShot)
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
        let (channel, receiver) = self.client.listener.expect();
        let _: m::Empty = self
            .client
            .call(m::PTY_OPEN, &m::PtyOpenParams {
                sandbox_id: self.sandbox_id.as_str().to_owned(),
                pty_id: pty_id.clone(),
                channel,
                options: options.clone(),
            })
            .await?;
        let Channel { reader, writer } = receiver.accept_soon().await?;
        Ok(Box::new(RemotePtySession {
            client: Arc::clone(&self.client),
            pty_id,
            reader: AsyncMutex::new(reader),
            writer: AsyncMutex::new(writer),
        }))
    }
}

struct RemotePtySession {
    client: Arc<Client>,
    pty_id: String,
    reader: AsyncMutex<FrameReader<OwnedReadHalf>>,
    writer: AsyncMutex<FrameWriter<OwnedWriteHalf>>,
}

#[async_trait]
impl PtySession for RemotePtySession {
    async fn write_input(&self, bytes: &[u8]) -> Result<()> {
        self.writer
            .lock()
            .await
            .write(FrameKind::Stdin, bytes)
            .await
    }

    async fn read_output(&self) -> Result<Option<Vec<u8>>> {
        loop {
            match self.reader.lock().await.read().await? {
                Some((FrameKind::Stdout | FrameKind::Stderr, payload)) => {
                    return Ok(Some(payload));
                }
                Some((FrameKind::Eof, _)) | None => return Ok(None),
                Some(_) => {}
            }
        }
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
        let _ = self.writer.lock().await.finish().await;
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
        let (channel, receiver) = self.client.listener.expect();
        follow_log_stream(
            &self.client,
            m::LOGS_FOLLOW,
            &m::LogsFollowParams {
                sandbox_id: self.sandbox_id.as_str().to_owned(),
                stream_id: stream_id.clone(),
                channel,
                source,
            },
            &stream_id,
            receiver,
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
        let streaming = self.run_streaming(spec, ExecControls::default()).await?;
        Ok(streaming.result)
    }

    async fn run_streaming(
        &self,
        spec: &ExecSpec,
        controls: ExecControls,
    ) -> Result<ExecStreamingResult> {
        let exec_id = self.client.next_exec_id(&self.sandbox_id);
        let stdin = controls.stdin_reader(spec);
        let (channel, receiver) = self.client.listener.expect();
        let params = m::ExecStreamParams {
            sandbox_id: self.sandbox_id.as_str().to_owned(),
            exec_id: exec_id.clone(),
            channel,
            spec: m::ExecSpecDto::from_spec(spec),
            stdin: stdin.is_some(),
            retained_output_limit: controls.retained_output_limit,
        };
        run_channel_exec(
            &self.client,
            m::EXEC_STREAM,
            &params,
            &exec_id,
            receiver,
            stdin,
            &controls,
        )
        .await
    }

    async fn spawn_stdio(&self, spec: &SpawnSpec) -> Result<StdioProcess> {
        let process_id = self.client.next_stream_id("stdio");
        let (channel, receiver) = self.client.listener.expect();
        let _: m::Empty = self
            .client
            .call(m::EXEC_STDIO_OPEN, &m::StdioOpenParams {
                sandbox_id: self.sandbox_id.as_str().to_owned(),
                process_id: process_id.clone(),
                channel,
                spec: spec.clone(),
            })
            .await?;
        let Channel { mut reader, writer } = receiver.accept_soon().await?;

        let (stdin_writer, stdin_reader) = duplex(64 * 1024);
        let input_task = tokio::spawn(feed_stdin_frames(Box::pin(stdin_reader), writer));

        let (mut stdout_writer, stdout_reader) = duplex(64 * 1024);
        let stderr_tail = StderrTail::default();
        let output_tail = stderr_tail.clone();
        let output_id = process_id.clone();
        let output_task = tokio::spawn(async move {
            loop {
                match reader.read().await {
                    Ok(Some((FrameKind::Stdout, payload))) => {
                        if stdout_writer.write_all(&payload).await.is_err() {
                            tracing::debug!(
                                process_id = %output_id,
                                "plugin stdio output reader closed"
                            );
                            break;
                        }
                    }
                    Ok(Some((FrameKind::Stderr, payload))) => output_tail.push(&payload),
                    Ok(Some((FrameKind::Eof, _)) | None) => break,
                    Ok(Some(_)) => {}
                    Err(error) => {
                        tracing::warn!(
                            process_id = %output_id,
                            error = %error,
                            "plugin stdio output channel failed"
                        );
                        break;
                    }
                }
            }
            let _ = stdout_writer.shutdown().await;
        });

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

struct SandboxOneShot {
    client:     Arc<Client>,
    sandbox_id: SandboxId,
}

#[async_trait]
impl OneShot for SandboxOneShot {
    async fn run(&self, spec: &OneShotSpec, controls: ExecControls) -> Result<ExecStreamingResult> {
        let exec_id = self.client.next_exec_id(&self.sandbox_id);
        let (channel, receiver) = self.client.listener.expect();
        let params = m::OneShotRunParams {
            sandbox_id: self.sandbox_id.as_str().to_owned(),
            exec_id: exec_id.clone(),
            channel,
            spec: spec.clone(),
            retained_output_limit: controls.retained_output_limit,
        };
        run_channel_exec(
            &self.client,
            m::ONE_SHOT_RUN,
            &params,
            &exec_id,
            receiver,
            None,
            &controls,
        )
        .await
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
    #[tracing::instrument(skip_all, fields(process_id = %self.process_id))]
    async fn terminate(&self) {
        let outcome: Result<m::Empty> = self
            .client
            .call(m::EXEC_STDIO_TERMINATE, &m::StdioIdParams {
                process_id: self.process_id.clone(),
            })
            .await;
        if let Err(error) = outcome {
            tracing::warn!(error = %error, "plugin stdio termination failed");
        }
    }

    #[tracing::instrument(skip_all, fields(process_id = %self.process_id))]
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
                let result = match result {
                    Ok(result) => result,
                    Err(error) => {
                        tracing::error!(error = %error, "plugin stdio wait failed");
                        return (Termination::Unknown, None);
                    }
                };
                if let Some(task) = self.output_task.lock().await.take() {
                    if let Err(error) = task.await {
                        tracing::error!(error = ?error, "plugin stdio output task failed");
                    }
                }
                if !result.stderr_tail.is_empty() {
                    self.stderr_tail.push(result.stderr_tail.as_bytes());
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

    async fn read_through_channel(
        &self,
        path: &str,
        offset: Option<u64>,
        length: Option<u64>,
    ) -> Result<Vec<u8>> {
        let (channel, receiver) = self.client.listener.expect();
        let accepted = Arc::new(AtomicBool::new(false));
        let collect_accepted = Arc::clone(&accepted);
        let collect = tokio::spawn(async move {
            let Channel { mut reader, .. } = receiver.accept().await?;
            collect_accepted.store(true, Ordering::SeqCst);
            let mut content = Vec::new();
            loop {
                match reader.read().await? {
                    Some((FrameKind::Stdout, payload)) => content.extend(payload),
                    Some((FrameKind::Eof, _)) | None => return Ok(content),
                    Some(_) => {}
                }
            }
        });
        let outcome: Result<m::Empty> = self
            .client
            .call(m::FS_READ, &m::FsReadParams {
                sandbox_id: self.sandbox_id.as_str().to_owned(),
                path: path.to_owned(),
                channel,
                offset,
                length,
            })
            .await;
        if let Err(error) = outcome {
            collect.abort();
            return Err(error);
        }
        join_pump(collect, &accepted, m::FS_READ).await
    }

    async fn write_through_channel(&self, path: &str, content: &[u8], append: bool) -> Result<()> {
        let (channel, receiver) = self.client.listener.expect();
        let accepted = Arc::new(AtomicBool::new(false));
        let send_accepted = Arc::clone(&accepted);
        let content = content.to_vec();
        let send = tokio::spawn(async move {
            let Channel { mut writer, .. } = receiver.accept().await?;
            send_accepted.store(true, Ordering::SeqCst);
            writer.write(FrameKind::Stdin, &content).await?;
            writer.finish().await
        });
        let outcome: Result<m::Empty> = self
            .client
            .call(m::FS_WRITE, &m::FsWriteParams {
                sandbox_id: self.sandbox_id.as_str().to_owned(),
                path: path.to_owned(),
                channel,
                append,
            })
            .await;
        if let Err(error) = outcome {
            send.abort();
            return Err(error);
        }
        join_pump(send, &accepted, m::FS_WRITE).await
    }
}

#[async_trait]
impl Filesystem for SandboxFs {
    async fn read(&self, path: &str) -> Result<Vec<u8>> {
        self.read_through_channel(path, None, None).await
    }

    async fn read_range(&self, path: &str, offset: u64, length: Option<u64>) -> Result<Vec<u8>> {
        self.read_through_channel(path, Some(offset), length).await
    }

    async fn write(&self, path: &str, content: &[u8]) -> Result<()> {
        self.write_through_channel(path, content, false).await
    }

    async fn write_append(&self, path: &str, content: &[u8]) -> Result<()> {
        self.write_through_channel(path, content, true).await
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
        // The channel carries any size in bounded frames; the file is read
        // once and written once.
        let content = tokio_fs::read(local)
            .await
            .map_err(|error| Error::io(format!("reading {}", local.display()), error))?;
        self.write(remote, &content).await
    }

    async fn download(&self, remote: &str, local: &Path) -> Result<()> {
        let content = self.read(remote).await?;
        if let Some(parent) = local.parent() {
            tokio_fs::create_dir_all(parent).await.map_err(|error| {
                Error::io(format!("creating parent of {}", local.display()), error)
            })?;
        }
        tokio_fs::write(local, content)
            .await
            .map_err(|error| Error::io(format!("writing {}", local.display()), error))
    }
}
