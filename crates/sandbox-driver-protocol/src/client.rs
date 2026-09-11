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
use std::future::Future;
use std::io;
use std::path::Path;
use std::pin::pin;
use std::process::{self, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use sandbox_driver::{
    Capabilities, Capability, DerivedGit, DirEntry, Error, EventContext, EventSubject, Exec,
    ExecControls, ExecResult, ExecSpec, ExecStreamingResult, FileMetadata, Filesystem, ForkOptions,
    Git, GitBranches, GitCheckoutOptions, GitCloneOptions, GitCommitOptions, GitCredentials,
    GitPushOptions, GitStatus, HealthStatus, IncompleteOperation, LifecycleTimers, LogSink,
    LogSource, Logs, NetworkPolicy, OneShot, OneShotSpec, OutputCaptureBuffer, OutputStream,
    PlatformInfo, PreviewUrl, PreviewUrls, ProviderHealth, ProviderKind, Pty, PtyOptions,
    PtySession, PtySize, Resources, Result, Sandbox, SandboxFilter, SandboxId,
    SandboxSnapshotOptions, SandboxSpec, SandboxStatus, SnapshotFilter, SnapshotId,
    SnapshotProvider, SnapshotSpec, SnapshotStatus, SpawnSpec, SshAccess, SshAccessInfo,
    StderrTail, StdinReader, StdioProcess, StdioProcessHandle, StopLevel, Termination,
    TransportError, Vnc, VncConnection, VolumeId, VolumeProvider, VolumeSpec, VolumeStatus,
    WebTerminal,
};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, duplex};
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::process::{Child, Command};
use tokio::runtime::Handle as RuntimeHandle;
use tokio::sync::{Mutex as AsyncMutex, OnceCell, OwnedSemaphorePermit, Semaphore, mpsc, oneshot};
use tokio::task::{JoinHandle, JoinSet};
use tokio::{fs as tokio_fs, time};
use tokio_util::sync::CancellationToken;
use tokio_util::task::AbortOnDropHandle;
use tracing::field;

use crate::channel::{
    Channel, ChannelListener, ChannelReceiver, FrameKind, FrameReader, FrameWriter, TrustedPeer,
};
use crate::wire::Message;
use crate::{TransportDiagnostics, TransportLimits, control, limits, methods as m};

/// How long the host waits, after a plugin has answered an operation,
/// for the data channel that operation must already have opened.
const LATE_CHANNEL_GRACE: Duration = Duration::from_secs(10);
/// The entire shutdown exchange, including acknowledgment and process exit.
#[cfg(test)]
const SHUTDOWN_GRACE: Duration = Duration::from_secs(5);

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
        Self::connect_with_limits(
            reader,
            writer,
            TransportLimits::default(),
            TrustedPeer::Process(process::id()),
        )
        .await
    }

    /// Connects to an explicitly trusted data peer with finite transport
    /// budgets.
    pub async fn connect_with_limits(
        reader: impl AsyncRead + Unpin + Send + 'static,
        writer: impl AsyncWrite + Unpin + Send + 'static,
        limits: TransportLimits,
        peer: TrustedPeer,
    ) -> Result<Self> {
        let listener = ChannelListener::bind_with_limits(limits.clone(), peer)?;
        let transport = listener.transport();
        let client = Client::start(reader, writer, listener, limits);
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
    pub async fn spawn(command: Command) -> Result<Self> {
        Self::spawn_with_limits(command, TransportLimits::default()).await
    }

    pub async fn spawn_with_limits(mut command: Command, limits: TransportLimits) -> Result<Self> {
        limits.validate()?;
        command.stdin(Stdio::piped());
        command.stdout(Stdio::piped());
        command.kill_on_drop(true);
        let mut child = command
            .spawn()
            .map_err(|error| Error::io("spawning plugin process", error))?;
        let stdin = child.stdin.take().expect("stdin was piped");
        let stdout = child.stdout.take().expect("stdout was piped");
        let pid = child.id().ok_or_else(|| {
            Error::Transport(TransportError::new("plugin exited before initialization"))
        })?;
        let mut provider =
            Self::connect_with_limits(stdout, stdin, limits, TrustedPeer::Process(pid)).await?;
        provider.child = Some(Mutex::new(Some(child)));
        Ok(provider)
    }

    /// Whether the control transport is still open. `false` once the
    /// plugin exited or its stdio broke; every later call fails at once.
    pub fn is_closed(&self) -> bool {
        self.client.closed.load(Ordering::SeqCst)
    }

    /// Snapshot local ownership and plugin registries. Older peers may not
    /// implement the optional `transport/diagnostics` method.
    pub async fn transport_diagnostics(&self) -> Result<TransportDiagnostics> {
        let server = self
            .client
            .call(m::TRANSPORT_DIAGNOSTICS, &m::Empty)
            .await?;
        let mut client = self.client.listener.diagnostics();
        client.stop_requests = self.client.stop_requests.load(Ordering::Relaxed);
        client.stop_acknowledgments = self.client.stop_acknowledgments.load(Ordering::Relaxed);
        client.max_stop_acknowledgment_us = self
            .client
            .max_stop_acknowledgment_us
            .load(Ordering::Relaxed);
        client.pending_requests = self.client.pending.lock().expect("pending lock").len();
        let mut cleanup = self.client.cleanup.lock().expect("cleanup tasks lock");
        while cleanup.try_join_next().is_some() {}
        client.cleanup_tasks = cleanup.len();
        client.failed_cleanups = self
            .client
            .failed_cleanup
            .lock()
            .expect("failed cleanup lock")
            .len();
        client.event_routes = self
            .client
            .event_routes
            .lock()
            .expect("event routes lock")
            .len();
        client.event_contexts = self
            .client
            .event_contexts
            .lock()
            .expect("event contexts lock")
            .len();
        client.runtime_tasks = RuntimeHandle::current().metrics().num_alive_tasks();
        Ok(TransportDiagnostics { client, server })
    }

    /// Takes the bounded recent channel-setup measurements, in microseconds.
    pub fn take_channel_setup_samples_us(&self) -> Vec<u64> {
        self.client.listener.take_setup_samples_us()
    }

    /// PID for process supervision and resource measurements, when spawned.
    pub fn process_id(&self) -> Option<u32> {
        self.child.as_ref().and_then(|slot| {
            slot.lock()
                .expect("child lock")
                .as_ref()
                .and_then(Child::id)
        })
    }

    /// Failure of this connection's ordered event subscription. Control calls
    /// continue, but applications must treat the event history as incomplete.
    pub fn event_delivery_error(&self) -> Option<TransportError> {
        self.client
            .event_failure
            .lock()
            .expect("event failure lock")
            .clone()
    }

    /// Last failed or timed-out local cleanup. Its I/O admission remains
    /// occupied until this connection is dropped; other operations continue.
    pub fn cleanup_error(&self) -> Option<TransportError> {
        self.client
            .failed_cleanup
            .lock()
            .expect("failed cleanup lock")
            .last()
            .map(|(_, error)| error.clone())
    }

    /// Asks the plugin to shut down cleanly and reaps a spawned child.
    /// Acknowledgment and process exit share a five-second deadline;
    /// failure or timeout kills the child and returns an error.
    #[tracing::instrument(skip_all, fields(provider_kind = %self.kind), err)]
    pub async fn shutdown(&self) -> Result<()> {
        let mut child = self
            .child
            .as_ref()
            .and_then(|slot| slot.lock().expect("child lock").take());
        let outcome = time::timeout(self.client.limits.shutdown_timeout, async {
            let _: m::Empty = self.client.call(m::SHUTDOWN, &m::Empty).await?;
            if let Some(child) = &mut child {
                child
                    .wait()
                    .await
                    .map_err(|error| Error::io("reaping plugin process", error))?;
            }
            Ok(())
        })
        .await
        .unwrap_or_else(|_| {
            Err(Error::Transport(TransportError::new(
                "plugin shutdown timed out before acknowledgment or process exit",
            )))
        });
        if outcome.is_err() {
            if let Some(child) = &mut child {
                if let Err(error) = child.start_kill() {
                    tracing::warn!(provider_kind = %self.kind, error = ?error, "plugin process kill failed");
                }
                // Do not add an unbounded wait after the deadline. Tokio's
                // child drop transfers any remaining reap to its reaper.
            }
        }
        outcome
    }

    fn wrap_handle(
        &self,
        mut info: m::HandleInfo,
        events: Option<EventContext>,
    ) -> Arc<dyn Sandbox> {
        mask_wire_capabilities(&mut info.capabilities);
        let id = info.status.id.clone();
        if let Some(context) = &events {
            let mut contexts = self
                .client
                .event_contexts
                .lock()
                .expect("event contexts lock");
            if contexts.len() >= self.client.limits.cached_handles {
                if let Some(old) = contexts.keys().next().cloned() {
                    contexts.remove(&old);
                }
            }
            contexts.insert(id.as_str().to_owned(), context.clone());
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
        outcome?;
        Ok(())
    }

    async fn build_logs(&self, id: &SnapshotId, follow: bool, sink: LogSink) -> Result<()> {
        let stream_id = self.client.next_stream_id("snapshot");
        let (channel, receiver) = self.client.listener.expect()?;
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

    async fn release_preview_url(&self, port: u16) -> Result<()> {
        let outcome: Result<m::Empty> = self
            .client
            .call(m::ACCESS_PREVIEW_RELEASE, &m::PreviewUrlParams {
                sandbox_id: self.sandbox_id.as_str().to_owned(),
                port,
            })
            .await;
        match outcome {
            Ok(_) => Ok(()),
            // A plugin predating the method holds nothing for a preview
            // URL, so there is nothing to release.
            Err(Error::Provider(provider)) if provider.code.as_deref() == Some("-32601") => Ok(()),
            Err(error) => Err(error),
        }
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
/// Native search/service passthrough and local shell commands remain
/// process-local; everything else, streamed stdin, the effective
/// environment, and the provider's own git clone included, crosses in
/// version 2. `git.native` stays as declared: when true the host sends
/// `git/clone` so the plugin runs its native clone, and the host derives
/// the remaining operations either way.
fn mask_wire_capabilities(capabilities: &mut Capabilities) {
    capabilities.search.native = false;
    capabilities.services.native = false;
    capabilities.access.shell_command = false;
}

/// Request/response correlation plus notification routing.
///
/// The reader task never awaits consumer code: it only resolves pending
/// calls and forwards events. Every byte stream has a connection of its
/// own, pumped by the operation that asked for it.
struct Client {
    outbound: control::ControlSender,
    limits: TransportLimits,
    requests: Arc<Semaphore>,
    reserved: Arc<Semaphore>,
    events: mpsc::Sender<DeliveredEvent>,
    event_bytes: Arc<Semaphore>,
    event_failure: Mutex<Option<TransportError>>,
    listener: ChannelListener,
    next_id: AtomicU64,
    next_exec: AtomicU64,
    next_stream: AtomicU64,
    next_operation: AtomicU64,
    stop_requests: AtomicU64,
    stop_acknowledgments: AtomicU64,
    max_stop_acknowledgment_us: AtomicU64,
    /// Set when either transport task ends; every pending and future call
    /// fails fast instead of waiting on a dead pipe.
    closed: AtomicBool,
    closed_signal: CancellationToken,
    cleanup: Mutex<JoinSet<()>>,
    failed_cleanup: Mutex<Vec<(Arc<OwnedSemaphorePermit>, TransportError)>>,
    closed_error: Mutex<Option<TransportError>>,
    pending: Mutex<HashMap<u64, oneshot::Sender<Result<Value>>>>,
    event_contexts: Mutex<HashMap<String, EventContext>>,
    /// Contexts for in-flight resource operations, keyed by a wire-only
    /// route id so events can arrive before a resource id exists.
    event_routes: Mutex<HashMap<String, EventContext>>,
    tasks: OnceLock<[AbortOnDropHandle<()>; 3]>,
}

struct DeliveredEvent {
    context: EventContext,
    event:   sandbox_driver::Event,
    _bytes:  OwnedSemaphorePermit,
}

struct PendingCall<'a> {
    pending: &'a Mutex<HashMap<u64, oneshot::Sender<Result<Value>>>>,
    id:      u64,
}

impl Drop for PendingCall<'_> {
    fn drop(&mut self) {
        self.pending.lock().expect("pending lock").remove(&self.id);
    }
}

impl Client {
    fn start(
        reader: impl AsyncRead + Unpin + Send + 'static,
        writer: impl AsyncWrite + Unpin + Send + 'static,
        listener: ChannelListener,
        limits: TransportLimits,
    ) -> Arc<Self> {
        let (outbound, mut outbound_rx) = control::queue(&limits);
        let (events, mut event_rx) = mpsc::channel::<DeliveredEvent>(limits.event_queue_messages);
        let progress_timeout = limits.output_progress_timeout;
        let max_message = limits.control_message_bytes;
        let listener_failed = listener.failure_signal();
        let client = Arc::new(Self {
            outbound,
            events,
            event_bytes: Arc::new(Semaphore::new(limits.event_queue_bytes)),
            event_failure: Mutex::new(None),
            requests: Arc::new(Semaphore::new(limits.provider_requests)),
            reserved: Arc::new(Semaphore::new(limits.reserved_requests)),
            limits,
            listener,
            next_id: AtomicU64::new(1),
            next_exec: AtomicU64::new(1),
            next_stream: AtomicU64::new(1),
            next_operation: AtomicU64::new(1),
            stop_requests: AtomicU64::new(0),
            stop_acknowledgments: AtomicU64::new(0),
            max_stop_acknowledgment_us: AtomicU64::new(0),
            closed: AtomicBool::new(false),
            closed_signal: CancellationToken::new(),
            cleanup: Mutex::new(JoinSet::new()),
            failed_cleanup: Mutex::new(Vec::new()),
            closed_error: Mutex::new(None),
            pending: Mutex::new(HashMap::new()),
            event_contexts: Mutex::new(HashMap::new()),
            event_routes: Mutex::new(HashMap::new()),
            tasks: OnceLock::new(),
        });

        let writer_client = Arc::downgrade(&client);
        let writer_task = tokio::spawn(async move {
            let mut writer = writer;
            let outcome: Result<(), TransportError> = async {
                while let Some(message) = outbound_rx.recv().await {
                    time::timeout(progress_timeout, writer.write_all(&message.bytes))
                        .await
                        .map_err(|_| TransportError::new("plugin control writer made no progress"))?
                        .map_err(|error| {
                            TransportError::with_source("writing plugin request", error)
                        })?;
                }
                writer.shutdown().await.map_err(|error| {
                    TransportError::with_source("shutting down plugin writer", error)
                })?;
                Ok(())
            }
            .await;
            if let Some(client) = writer_client.upgrade() {
                client.mark_closed(
                    outcome
                        .err()
                        .unwrap_or_else(|| TransportError::new("plugin request transport closed")),
                );
            }
        });

        let reader_client = Arc::downgrade(&client);
        let reader_task = tokio::spawn(async move {
            let mut reader = BufReader::new(reader);
            let mut partial = Vec::new();
            let outcome: Result<(), TransportError> = async {
                loop {
                    let line = tokio::select! {
                        line = control::read_line(&mut reader, &mut partial, max_message) => line,
                        () = listener_failed.cancelled() => return Err(TransportError::new("data listener failed")),
                    };
                    let Some(line) = line.map_err(|error| {
                            TransportError::with_source("reading plugin response", error)
                        })?
                    else {
                        return Ok(());
                    };
                    if line.iter().all(u8::is_ascii_whitespace) {
                        continue;
                    }
                    let message = serde_json::from_slice::<Message>(&line).map_err(|error| {
                        TransportError::with_source("decoding plugin response", error)
                    })?;
                    let Some(client) = reader_client.upgrade() else {
                        return Ok(());
                    };
                    client.route(message, line.len())?;
                }
            }
            .await;
            if let Some(client) = reader_client.upgrade() {
                client.mark_closed(
                    outcome
                        .err()
                        .unwrap_or_else(|| TransportError::new("plugin response transport closed")),
                );
            }
        });
        let event_client = Arc::downgrade(&client);
        let event_task = tokio::spawn(async move {
            while let Some(delivery) = event_rx.recv().await {
                let Some(client) = event_client.upgrade() else {
                    return;
                };
                if client
                    .event_failure
                    .lock()
                    .expect("event failure lock")
                    .is_some()
                {
                    return;
                }
                let timeout = client.limits.output_progress_timeout;
                drop(client);
                if time::timeout(timeout, delivery.context.forward(delivery.event))
                    .await
                    .is_err()
                {
                    if let Some(client) = event_client.upgrade() {
                        *client.event_failure.lock().expect("event failure lock") =
                            Some(TransportError::new(
                                "event observer timed out; event subscription is incomplete",
                            ));
                    }
                    return;
                }
            }
        });
        let _ = client.tasks.set([
            AbortOnDropHandle::new(writer_task),
            AbortOnDropHandle::new(reader_task),
            AbortOnDropHandle::new(event_task),
        ]);

        client
    }

    /// Marks the transport dead and fails everything pending. Called by
    /// both transport tasks; also re-checked by `call` after registering,
    /// closing the race where a call lands just after the drain.
    fn mark_closed(&self, error: TransportError) {
        self.closed_signal.cancel();
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

    async fn pump<R, T>(
        &self,
        call: impl Future<Output = Result<R>>,
        pump: impl Future<Output = Result<T>>,
        accepted: &AtomicBool,
        method: &str,
    ) -> Result<(R, T)> {
        let responded = AtomicBool::new(false);
        let call = async {
            let result = call.await?;
            responded.store(true, Ordering::SeqCst);
            Ok(result)
        };
        let mut operation = pin!(call_with_pump(call, pump, accepted, method));
        tokio::select! {
            biased;
            result = &mut operation => result,
            () = self.closed_signal.cancelled() => {
                // Graceful shutdown may close control after a response while
                // its final data frames still await scheduling on this side.
                if responded.load(Ordering::SeqCst) {
                    time::timeout(self.limits.hard_cancel_drain_timeout, operation).await
                        .unwrap_or_else(|_| Err(self.closed_error()))
                } else { Err(self.closed_error()) }
            }
        }
    }

    async fn cleanup_call<P: Serialize>(&self, method: &str, params: &P) -> Result<()> {
        loop {
            match self.call::<_, m::Empty>(method, params).await {
                Err(Error::Overloaded { .. }) => time::sleep(Duration::from_millis(1)).await,
                outcome => return outcome.map(|_| ()),
            }
        }
    }

    fn own_cleanup(
        self: &Arc<Self>,
        permit: Arc<OwnedSemaphorePermit>,
        future: impl Future<Output = Result<()>> + Send + 'static,
    ) {
        if RuntimeHandle::try_current().is_err() {
            self.failed_cleanup
                .lock()
                .expect("failed cleanup lock")
                .push((
                    permit,
                    TransportError::new("cleanup could not run without a runtime"),
                ));
            return;
        }
        let mut tasks = self.cleanup.lock().expect("cleanup tasks lock");
        while tasks.try_join_next().is_some() {}
        // Each task retains the original operation's I/O permit. The number
        // of running or failed cleanups therefore cannot exceed active_io.
        let weak = Arc::downgrade(self);
        let deadline = self.limits.shutdown_timeout;
        tasks.spawn(async move {
            let error = match time::timeout(deadline, future).await {
                Ok(Ok(())) => return,
                Ok(Err(_)) => TransportError::new("resource cleanup failed"),
                Err(_) => TransportError::new("resource cleanup timed out"),
            };
            if let Some(client) = weak.upgrade() {
                client
                    .failed_cleanup
                    .lock()
                    .expect("failed cleanup lock")
                    .push((permit, error));
            }
        });
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
            let mut routes = self.event_routes.lock().expect("event routes lock");
            // Responses can overtake asynchronous events. Keep completed routes
            // in a bounded cache; a late event for an evicted route explicitly
            // fails the event subscription instead of disappearing silently.
            if routes.len() >= self.limits.cached_handles {
                if let Some(old) = routes.keys().next().cloned() {
                    routes.remove(&old);
                }
            }
            routes.insert(route_id.clone(), context.clone());
            m::EventRequest {
                route_id,
                correlation_id: context.correlation_id_ref().cloned(),
            }
        })
    }

    fn route(&self, message: Message, bytes: usize) -> Result<(), TransportError> {
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
        if method == "host/event_failed" {
            *self.event_failure.lock().expect("event failure lock") = Some(TransportError::new(
                "plugin event subscription exceeded its delivery capacity",
            ));
        }
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
            if context.is_none() {
                *self.event_failure.lock().expect("event failure lock") = Some(
                    TransportError::new("event route expired; event subscription is incomplete"),
                );
            }
            if let Some(context) = context {
                let mut failure = self.event_failure.lock().expect("event failure lock");
                if failure.is_none() {
                    let permit = Arc::clone(&self.event_bytes)
                        .try_acquire_many_owned(u32::try_from(bytes).expect("bounded message"));
                    let delivered = permit.ok().is_some_and(|permit| {
                        self.events
                            .try_send(DeliveredEvent {
                                context,
                                event: notification.event,
                                _bytes: permit,
                            })
                            .is_ok()
                    });
                    if !delivered {
                        *failure = Some(TransportError::new(
                            "event delivery capacity exceeded; event subscription is incomplete",
                        ));
                    }
                }
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
        let priority = limits::reserved(method);
        let _admission = limits::acquire(
            if priority {
                &self.reserved
            } else {
                &self.requests
            },
            if priority {
                "reserved_requests"
            } else {
                "provider_requests"
            },
        )?;
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
        let _pending = PendingCall {
            pending: &self.pending,
            id,
        };
        if self.closed.load(Ordering::SeqCst) {
            // The transport may have died between the drain and our
            // registration. The guard removes this call on return.
            return Err(self.closed_error());
        }
        self.outbound
            .send(&Message::request(id, method, params), priority)?;
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
        acknowledged: Arc<AtomicBool>,
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
                    if level == StopLevel::Kill {
                        acknowledged.store(client.send_stop(&exec_id, level).await, Ordering::SeqCst);
                        break;
                    }
                    tokio::select! {
                        _ = client.send_stop(&exec_id, level) => {},
                        () = &mut killed => {
                            acknowledged.store(client.send_stop(&exec_id, StopLevel::Kill).await, Ordering::SeqCst);
                            break;
                        }
                    }
                    term_sent = true;
                }
            })
        })
    }

    async fn send_stop(&self, exec_id: &str, level: StopLevel) -> bool {
        self.stop_requests.fetch_add(1, Ordering::Relaxed);
        let started = Instant::now();
        loop {
            let outcome: Result<m::Empty> = self
                .call(m::EXEC_STOP, &m::ExecStopParams {
                    exec_id: exec_id.to_owned(),
                    level,
                })
                .await;
            match outcome {
                Ok(_) => {
                    self.stop_acknowledgments.fetch_add(1, Ordering::Relaxed);
                    self.max_stop_acknowledgment_us.fetch_max(
                        u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX),
                        Ordering::Relaxed,
                    );
                    return true;
                }
                // Admitted operations already bound the number of stop tasks.
                // Retry delivery inside the local drain deadline; do not lose
                // an already-fired kill token when the reserve is briefly full.
                Err(Error::Overloaded { .. }) => time::sleep(Duration::from_millis(1)).await,
                Err(error) => {
                    tracing::warn!(error = %error, ?level, "plugin exec stop failed");
                    return false;
                }
            }
        }
    }
}

/// Polls the control call and data pump together. Both futures belong to
/// this operation, so cancellation drops the channel and its expectation.
async fn call_with_pump<R, T>(
    call: impl Future<Output = Result<R>>,
    pump: impl Future<Output = Result<T>>,
    accepted: &AtomicBool,
    method: &str,
) -> Result<(R, T)> {
    let mut call = pin!(call);
    let mut pump = pin!(pump);
    tokio::select! {
        pumped = &mut pump => {
            let pumped = pumped?;
            Ok((call.await?, pumped))
        },
        result = &mut call => {
            let result = result?;
            let pumped = if accepted.load(Ordering::SeqCst) {
                pump.await?
            } else {
                time::timeout(LATE_CHANNEL_GRACE, pump).await.map_err(|_| {
                    Error::Transport(TransportError::new(format!(
                        "the plugin answered {method} without opening its data channel"
                    )))
                })??
            };
            Ok((result, pumped))
        }
    }
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
    controls: ExecControls,
    acknowledged: Arc<AtomicBool>,
) -> Result<PumpedOutput> {
    let Channel { mut reader, writer } = receiver.accept().await?;
    accepted.store(true, Ordering::SeqCst);
    // The server registers stop tokens before opening this channel. Waiting
    // for acceptance prevents an already-cancelled token overtaking exec.
    let _stop_task = client
        .forward_stops(&exec_id, &controls, acknowledged)
        .map(AbortOnDropHandle::new);
    let input_error = Arc::new(Mutex::new(None));
    let _stdin_task = stdin.map(|reader| {
        let input_error = Arc::clone(&input_error);
        let kill = controls.kill.clone();
        AbortOnDropHandle::new(tokio::spawn(async move {
            if let Err(error) = feed_stdin_frames(reader, writer).await {
                *input_error.lock().expect("input error lock") = Some(error);
                if let Some(kill) = kill {
                    kill.cancel();
                }
            }
        }))
    });
    let mut output = PumpedOutput {
        stdout:     OutputCaptureBuffer::new(controls.retained_output_limit),
        stderr:     OutputCaptureBuffer::new(controls.retained_output_limit),
        sink_error: None,
    };
    loop {
        let Some(frame) = reader.read().await? else {
            break;
        };
        let (stream, payload) = match frame {
            (FrameKind::Stdout, payload) => (OutputStream::Stdout, payload),
            (FrameKind::Stderr, payload) => (OutputStream::Stderr, payload),
            (FrameKind::Eof, _) => break,
            (kind, _) => {
                return Err(Error::invalid_spec(
                    "frame",
                    format!("unexpected {kind:?} frame on exec output"),
                ));
            }
        };
        match stream {
            OutputStream::Stdout => output.stdout.push(&payload),
            OutputStream::Stderr => output.stderr.push(&payload),
        }
        if output.sink_error.is_some() || payload.is_empty() {
            continue;
        }
        if let Some(sink) = &controls.sink {
            let delivered =
                time::timeout(client.limits.output_progress_timeout, sink(stream, payload))
                    .await
                    .unwrap_or_else(|_| {
                        Err(Error::Transport(TransportError::new(
                            "output sink made no progress",
                        )))
                    });
            if let Err(error) = delivered {
                // A failing sink is a hard stop on every provider; the
                // rest of the stream is drained and dropped.
                if let Some(kill) = &controls.kill {
                    kill.cancel();
                }
                output.sink_error = Some(error);
            }
        }
    }
    if let Some(error) = input_error.lock().expect("input error lock").take() {
        return Err(error);
    }
    Ok(output)
}

/// Copies `reader` into the channel as `Stdin` frames, then sends the
/// host's `Eof`. A channel the plugin closed is the command declining
/// its input, which is not an error.
async fn feed_stdin_frames(
    mut reader: StdinReader,
    mut writer: FrameWriter<OwnedWriteHalf>,
) -> Result<()> {
    let mut buffer = vec![0; 32 * 1024];
    loop {
        let read = reader
            .read(&mut buffer)
            .await
            .map_err(|error| Error::io("reading exec stdin source", error))?;
        if read == 0 {
            break;
        }
        // A process may close stdin without consuming all input. A source
        // read error, unlike that normal refusal, must fail the operation.
        if writer
            .write(FrameKind::Stdin, &buffer[..read])
            .await
            .is_err()
        {
            return Ok(());
        }
    }
    let _ = writer.finish().await;
    Ok(())
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
    if controls
        .retained_output_limit
        .is_some_and(|limit| limit > client.limits.retained_output_bytes)
    {
        return Err(Error::LimitExceeded {
            limit:     "retained_output_bytes".into(),
            max_bytes: client.limits.retained_output_bytes,
        });
    }
    let mut controls = controls.clone();
    let kill = controls
        .kill
        .get_or_insert_with(CancellationToken::new)
        .clone();
    let drain_deadline = async {
        kill.cancelled().await;
        time::sleep(client.limits.hard_cancel_drain_timeout).await;
    };
    let accepted = Arc::new(AtomicBool::new(false));
    let acknowledged = Arc::new(AtomicBool::new(false));
    let terminated = AtomicBool::new(false);
    let pump = pump_exec_channel(
        Arc::clone(client),
        exec_id.to_owned(),
        receiver,
        Arc::clone(&accepted),
        stdin,
        controls.clone(),
        Arc::clone(&acknowledged),
    );
    let execution = client.pump(
        async {
            let result = client
                .call::<_, m::ExecStreamResult>(method, params)
                .await?;
            terminated.store(
                matches!(
                    result.result.termination,
                    Termination::Exited | Termination::Killed
                ),
                Ordering::SeqCst,
            );
            Ok(result)
        },
        pump,
        &accepted,
        method,
    );
    let (result, pumped) = tokio::select! {
        result = execution => result?,
        () = drain_deadline => {
            let mut outcome = IncompleteOperation::new("hard cancellation drain");
            outcome.stop_acknowledged = acknowledged.load(Ordering::SeqCst);
            outcome.termination_confirmed = terminated.load(Ordering::SeqCst);
            return Err(Error::Incomplete(outcome));
        },
    };
    let (stdout, mut stdout_stats) = pumped.stdout.into_parts();
    let (stderr, mut stderr_stats) = pumped.stderr.into_parts();
    stdout_stats.truncated = result.stdout_capture.truncated || pumped.sink_error.is_some();
    stderr_stats.truncated = result.stderr_capture.truncated || pumped.sink_error.is_some();
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
    permit:    Option<Arc<OwnedSemaphorePermit>>,
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
        let permit = self.permit.take().expect("armed stream retains admission");
        self.client.own_cleanup(permit, async move {
            loop {
                match client
                    .call::<_, m::Empty>(m::STREAM_CANCEL, &m::StreamIdParams {
                        stream_id: stream_id.clone(),
                    })
                    .await
                {
                    Err(Error::Overloaded { .. }) => time::sleep(Duration::from_millis(1)).await,
                    outcome => return outcome.map(|_| ()),
                }
            }
        });
    }
}

/// Feeds a log channel to `sink` until the plugin's `Eof`. A sink error
/// ends the pump and is the caller's result.
async fn pump_log_channel(
    receiver: ChannelReceiver,
    accepted: Arc<AtomicBool>,
    sink: LogSink,
    timeout: Duration,
) -> Result<()> {
    let Channel { mut reader, .. } = receiver.accept().await?;
    accepted.store(true, Ordering::SeqCst);
    loop {
        match reader.read().await? {
            Some((FrameKind::Stdout | FrameKind::Stderr, payload)) => {
                time::timeout(timeout, sink(payload)).await.map_err(|_| {
                    Error::Transport(TransportError::new("log sink made no progress"))
                })??;
            }
            Some((FrameKind::Eof, _)) | None => return Ok(()),
            Some((kind, _)) => {
                return Err(Error::invalid_spec(
                    "frame",
                    format!("unexpected {kind:?} on a log channel"),
                ));
            }
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
        permit:    Some(receiver.io_permit()),
        client:    Arc::clone(client),
        stream_id: stream_id.to_owned(),
        armed:     true,
    };
    let accepted = Arc::new(AtomicBool::new(false));
    let call = async {
        let outcome = client.call::<_, m::Empty>(method, params).await;
        guard.armed = false;
        outcome
    };
    client
        .pump(
            call,
            pump_log_channel(
                receiver,
                Arc::clone(&accepted),
                sink,
                client.limits.output_progress_timeout,
            ),
            &accepted,
            method,
        )
        .await?;
    Ok(())
}

/// A sandbox handle backed by the plugin.
struct SandboxHandle {
    client:            Arc<Client>,
    id:                SandboxId,
    capabilities:      Capabilities,
    working_directory: String,
    runtime_directory: Option<String>,
    exec:              SandboxExec,
    git:               SandboxGit,
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
            git: SandboxGit {
                client:            Arc::clone(&client),
                sandbox_id:        id.clone(),
                exec:              SandboxExec {
                    client:     Arc::clone(&client),
                    sandbox_id: id.clone(),
                },
                runtime_directory: runtime_directory.clone(),
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

    fn provider_git(&self) -> Option<&dyn Git> {
        // A plugin whose clone is exec-derived runs exactly what the host's
        // derived git runs, so the host derives every operation itself and
        // the wire carries nothing extra. A native clone must run in the
        // plugin, so the host routes it through `git/clone`.
        self.capabilities
            .git
            .native
            .then_some(&self.git as &dyn Git)
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

/// The host side of a plugin sandbox's git facet, selected when the
/// plugin declares `git.native`: clone crosses the wire so the plugin runs
/// its native clone (Daytona's toolbox clone, say), and every other
/// operation is exec-derived here.
struct SandboxGit {
    client:            Arc<Client>,
    sandbox_id:        SandboxId,
    exec:              SandboxExec,
    runtime_directory: Option<String>,
}

impl SandboxGit {
    fn derived(&self) -> DerivedGit<'_> {
        let git = DerivedGit::new(&self.exec);
        match self.runtime_directory.as_deref() {
            Some(runtime_directory) => git.with_runtime_directory(runtime_directory),
            None => git,
        }
    }
}

#[async_trait]
impl Git for SandboxGit {
    async fn clone_repo(
        &self,
        url: &str,
        target_path: &str,
        options: &GitCloneOptions,
    ) -> Result<()> {
        options.validate()?;
        let outcome: Result<m::Empty> = self
            .client
            .call(m::GIT_CLONE, &m::GitCloneParams {
                sandbox_id:  self.sandbox_id.as_str().to_owned(),
                url:         url.to_owned(),
                target_path: target_path.to_owned(),
                options:     options.clone(),
            })
            .await;
        match outcome {
            Ok(_) => Ok(()),
            // A plugin predating `git/clone` served git through exec only;
            // the derived clone is what such a host ran before the method
            // existed, so the fallback changes nothing for it.
            Err(Error::Provider(provider)) if provider.code.as_deref() == Some("-32601") => {
                self.derived().clone_repo(url, target_path, options).await
            }
            Err(error) => Err(error),
        }
    }

    async fn status(&self, repo_path: &str) -> Result<GitStatus> {
        self.derived().status(repo_path).await
    }

    async fn add(&self, repo_path: &str, paths: &[String]) -> Result<()> {
        self.derived().add(repo_path, paths).await
    }

    async fn commit(&self, repo_path: &str, options: &GitCommitOptions) -> Result<String> {
        self.derived().commit(repo_path, options).await
    }

    async fn push(&self, repo_path: &str, options: &GitPushOptions) -> Result<()> {
        self.derived().push(repo_path, options).await
    }

    async fn pull(&self, repo_path: &str, credentials: Option<&GitCredentials>) -> Result<()> {
        self.derived().pull(repo_path, credentials).await
    }

    async fn branches(&self, repo_path: &str) -> Result<GitBranches> {
        self.derived().branches(repo_path).await
    }

    async fn checkout(&self, repo_path: &str, options: &GitCheckoutOptions) -> Result<()> {
        self.derived().checkout(repo_path, options).await
    }

    async fn set_ambient_credentials(
        &self,
        repo_path: &str,
        credentials: Option<&GitCredentials>,
    ) -> Result<()> {
        self.derived()
            .set_ambient_credentials(repo_path, credentials)
            .await
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
        let (channel, receiver) = self.client.listener.expect()?;
        let permit = receiver.io_permit();
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
            permit: Mutex::new(Some(permit)),
            closed: AtomicBool::new(false),
            pty_id,
            reader: AsyncMutex::new(Some(reader)),
            writer: AsyncMutex::new(Some(writer)),
        }))
    }
}

struct RemotePtySession {
    permit: Mutex<Option<Arc<OwnedSemaphorePermit>>>,
    closed: AtomicBool,
    client: Arc<Client>,
    pty_id: String,
    reader: AsyncMutex<Option<FrameReader<OwnedReadHalf>>>,
    writer: AsyncMutex<Option<FrameWriter<OwnedWriteHalf>>>,
}

impl Drop for RemotePtySession {
    fn drop(&mut self) {
        if self.closed.load(Ordering::SeqCst) {
            return;
        }
        let permit = self
            .permit
            .get_mut()
            .expect("PTY permit lock")
            .take()
            .expect("PTY retains admission");
        let client = Arc::clone(&self.client);
        let pty_id = self.pty_id.clone();
        self.client.own_cleanup(permit, async move {
            client
                .cleanup_call(m::PTY_CLOSE, &m::PtyIdParams { pty_id })
                .await
        });
    }
}

#[async_trait]
impl PtySession for RemotePtySession {
    async fn write_input(&self, bytes: &[u8]) -> Result<()> {
        self.writer
            .lock()
            .await
            .as_mut()
            .ok_or_else(|| Error::invalid_spec("pty", "session is closed"))?
            .write(FrameKind::Stdin, bytes)
            .await
    }

    async fn read_output(&self) -> Result<Option<Vec<u8>>> {
        let mut reader = self.reader.lock().await;
        let Some(reader) = reader.as_mut() else {
            return Ok(None);
        };
        match reader.read().await? {
            Some((FrameKind::Stdout | FrameKind::Stderr, payload)) => Ok(Some(payload)),
            Some((FrameKind::Eof, _)) | None => Ok(None),
            Some((kind, _)) => Err(Error::invalid_spec(
                "frame",
                format!("unexpected {kind:?} on PTY output"),
            )),
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
        time::timeout(self.client.limits.hard_cancel_drain_timeout, async {
            self.client
                .cleanup_call(m::PTY_CLOSE, &m::PtyIdParams {
                    pty_id: self.pty_id.clone(),
                })
                .await?;
            self.reader.lock().await.take();
            self.writer.lock().await.take();
            self.permit.lock().expect("PTY permit lock").take();
            self.closed.store(true, Ordering::SeqCst);
            Ok::<_, Error>(())
        })
        .await
        .map_err(|_| Error::Incomplete(IncompleteOperation::new("PTY close")))?
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
        let (channel, receiver) = self.client.listener.expect()?;
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
        let streaming = self
            .run_streaming(spec, ExecControls {
                retained_output_limit: Some(self.client.limits.retained_output_bytes),
                ..ExecControls::default()
            })
            .await?;
        streaming.into_complete()
    }

    async fn run_streaming(
        &self,
        spec: &ExecSpec,
        controls: ExecControls,
    ) -> Result<ExecStreamingResult> {
        let exec_id = self.client.next_exec_id(&self.sandbox_id);
        let stdin = controls.stdin_reader(spec);
        let (channel, receiver) = self.client.listener.expect()?;
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
        let (channel, receiver) = self.client.listener.expect()?;
        let permit = receiver.io_permit();
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
        let stopped = CancellationToken::new();
        let output_stopped = stopped.clone();
        let output_id = process_id.clone();
        let output_client = Arc::clone(&self.client);
        let output_task = tokio::spawn(async move {
            let outcome = async {
                loop {
                    match reader.read().await? {
                        Some((FrameKind::Stdout, payload)) => {
                            let mut bytes = payload.as_slice();
                            while !bytes.is_empty() {
                                let count = time::timeout(
                                    output_client.limits.output_progress_timeout,
                                    stdout_writer.write(bytes),
                                )
                                .await
                                .map_err(|_| {
                                    Error::Incomplete(IncompleteOperation::new(
                                        "stdio output progress",
                                    ))
                                })?
                                .map_err(|error| Error::io("writing stdio output", error))?;
                                if count == 0 {
                                    return Err(Error::io(
                                        "writing stdio output",
                                        io::ErrorKind::WriteZero.into(),
                                    ));
                                }
                                bytes = &bytes[count..];
                            }
                        }
                        Some((FrameKind::Stderr, payload)) => output_tail.push(&payload),
                        Some((FrameKind::Eof, _)) | None => return Ok(()),
                        Some((kind, _)) => {
                            return Err(Error::invalid_spec(
                                "frame",
                                format!("unexpected {kind:?} on stdio output"),
                            ));
                        }
                    }
                }
            }
            .await;
            if outcome.is_err() {
                output_stopped.cancel();
                let _ = time::timeout(
                    output_client.limits.hard_cancel_drain_timeout,
                    output_client.cleanup_call(m::EXEC_STDIO_TERMINATE, &m::StdioIdParams {
                        process_id: output_id,
                    }),
                )
                .await;
            }
            let _ = stdout_writer.shutdown().await;
            outcome
        });

        let handle = RemoteStdioHandle {
            client: Arc::clone(&self.client),
            permit: Mutex::new(Some(permit)),
            stopped,
            process_id,
            stderr_tail: stderr_tail.clone(),
            outcome: OnceCell::new(),
            input_task: AsyncMutex::new(Some(AbortOnDropHandle::new(input_task))),
            output_task: AsyncMutex::new(Some(AbortOnDropHandle::new(output_task))),
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
        let (channel, receiver) = self.client.listener.expect()?;
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
    permit:      Mutex<Option<Arc<OwnedSemaphorePermit>>>,
    stopped:     CancellationToken,
    client:      Arc<Client>,
    process_id:  String,
    stderr_tail: StderrTail,
    outcome:     OnceCell<(Termination, Option<i32>)>,
    input_task:  AsyncMutex<Option<AbortOnDropHandle<Result<()>>>>,
    output_task: AsyncMutex<Option<AbortOnDropHandle<Result<()>>>>,
}

impl Drop for RemoteStdioHandle {
    fn drop(&mut self) {
        let Some(permit) = self.permit.get_mut().expect("stdio permit lock").take() else {
            return;
        };
        let client = Arc::clone(&self.client);
        let process_id = self.process_id.clone();
        self.client.own_cleanup(permit, async move {
            let params = m::StdioIdParams { process_id };
            client
                .cleanup_call(m::EXEC_STDIO_TERMINATE, &params)
                .await?;
            loop {
                match client
                    .call::<_, m::StdioWaitResult>(m::EXEC_STDIO_WAIT, &params)
                    .await
                {
                    Err(Error::Overloaded { .. }) => time::sleep(Duration::from_millis(1)).await,
                    outcome => return outcome.map(|_| ()),
                }
            }
        });
    }
}

#[async_trait]
impl StdioProcessHandle for RemoteStdioHandle {
    #[tracing::instrument(skip_all, fields(process_id = %self.process_id))]
    async fn terminate(&self) {
        self.stopped.cancel();
        let outcome = time::timeout(
            self.client.limits.hard_cancel_drain_timeout,
            self.client
                .cleanup_call(m::EXEC_STDIO_TERMINATE, &m::StdioIdParams {
                    process_id: self.process_id.clone(),
                }),
        )
        .await;
        if !matches!(outcome, Ok(Ok(()))) {
            tracing::warn!("plugin stdio termination is unconfirmed");
        }
    }

    #[tracing::instrument(skip_all, fields(process_id = %self.process_id))]
    async fn wait(&self) -> (Termination, Option<i32>) {
        *self
            .outcome
            .get_or_init(|| async {
                let params = m::StdioIdParams { process_id: self.process_id.clone() };
                let result: Result<m::StdioWaitResult> = tokio::select! {
                    result = self.client.call(m::EXEC_STDIO_WAIT, &params) => result,
                    () = async { self.stopped.cancelled().await; time::sleep(self.client.limits.hard_cancel_drain_timeout).await; } => {
                        self.output_task.lock().await.take();
                        self.input_task.lock().await.take();
                        return (Termination::Unknown, None);
                    }
                };
                let result = match result {
                    Ok(result) => result,
                    Err(error) => {
                        tracing::error!(error = %error, "plugin stdio wait failed");
                        return (Termination::Unknown, None);
                    }
                };
                // The provider wait completed. Cleanup no longer needs to
                // retain separate admission, even if local output later fails.
                self.permit.lock().expect("stdio permit lock").take();
                if let Some(task) = self.output_task.lock().await.take() {
                    if !matches!(time::timeout(self.client.limits.hard_cancel_drain_timeout, task).await, Ok(Ok(Ok(())))) {
                        self.input_task.lock().await.take();
                        return (Termination::Unknown, None);
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
        output: &mut (dyn AsyncWrite + Unpin + Send),
    ) -> Result<()> {
        let (channel, receiver) = self.client.listener.expect()?;
        let accepted = Arc::new(AtomicBool::new(false));
        let collect_accepted = Arc::clone(&accepted);
        let collect = async move {
            let Channel { mut reader, .. } = receiver.accept().await?;
            collect_accepted.store(true, Ordering::SeqCst);
            loop {
                match reader.read().await? {
                    Some((FrameKind::Stdout, payload)) => {
                        let mut bytes = payload.as_slice();
                        while !bytes.is_empty() {
                            let written = time::timeout(
                                self.client.limits.output_progress_timeout,
                                output.write(bytes),
                            )
                            .await
                            .map_err(|_| {
                                Error::Transport(TransportError::new(
                                    "file output made no progress",
                                ))
                            })?
                            .map_err(|error| Error::io("writing downloaded file", error))?;
                            if written == 0 {
                                return Err(Error::io(
                                    "writing downloaded file",
                                    io::ErrorKind::WriteZero.into(),
                                ));
                            }
                            bytes = &bytes[written..];
                        }
                    }
                    Some((FrameKind::Eof, _)) | None => return Ok(()),
                    Some(_) => {
                        return Err(Error::invalid_spec(
                            "frame",
                            "unexpected frame on file output",
                        ));
                    }
                }
            }
        };
        let params = m::FsReadParams {
            sandbox_id: self.sandbox_id.as_str().to_owned(),
            path: path.to_owned(),
            channel,
            offset,
            length,
        };
        self.client
            .pump(
                self.client.call::<_, m::Empty>(m::FS_READ, &params),
                collect,
                &accepted,
                m::FS_READ,
            )
            .await?;
        Ok(())
    }

    async fn write_through_channel(
        &self,
        path: &str,
        input: &mut (dyn AsyncRead + Unpin + Send),
        length: u64,
        append: bool,
    ) -> Result<()> {
        let (channel, receiver) = self.client.listener.expect()?;
        let accepted = Arc::new(AtomicBool::new(false));
        let send_accepted = Arc::clone(&accepted);
        let send = async move {
            let Channel { mut writer, .. } = receiver.accept().await?;
            send_accepted.store(true, Ordering::SeqCst);
            let mut input = input.take(length);
            let mut buffer = vec![0; 64 * 1024];
            loop {
                let read = input
                    .read(&mut buffer)
                    .await
                    .map_err(|error| Error::io("reading upload source", error))?;
                if read == 0 {
                    if input.limit() != 0 {
                        return Err(Error::io(
                            "reading upload source",
                            io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "source ended before its declared length",
                            ),
                        ));
                    }
                    break;
                }
                writer.write(FrameKind::Stdin, &buffer[..read]).await?;
            }
            writer.finish().await
        };
        let params = m::FsWriteParams {
            sandbox_id: self.sandbox_id.as_str().to_owned(),
            path: path.to_owned(),
            channel,
            append,
            content_length: Some(length),
        };
        self.client
            .pump(
                self.client.call::<_, m::Empty>(m::FS_WRITE, &params),
                send,
                &accepted,
                m::FS_WRITE,
            )
            .await?;
        Ok(())
    }
}

#[async_trait]
impl Filesystem for SandboxFs {
    async fn read(&self, path: &str) -> Result<Vec<u8>> {
        let mut content =
            sandbox_driver::BoundedBuffer::new(self.client.limits.buffered_value_bytes);
        let outcome = self.read_to(path, &mut content).await;
        content.finish(outcome)
    }

    async fn read_range(&self, path: &str, offset: u64, length: Option<u64>) -> Result<Vec<u8>> {
        let mut content =
            sandbox_driver::BoundedBuffer::new(self.client.limits.buffered_value_bytes);
        let outcome = self
            .read_through_channel(path, Some(offset), length, &mut content)
            .await;
        content.finish(outcome)
    }

    async fn write(&self, path: &str, mut content: &[u8]) -> Result<()> {
        let length = content.len() as u64;
        self.write_from(path, &mut content, length).await
    }

    async fn write_append(&self, path: &str, mut content: &[u8]) -> Result<()> {
        let length = content.len() as u64;
        self.write_through_channel(path, &mut content, length, true)
            .await
    }

    async fn read_to(
        &self,
        path: &str,
        output: &mut (dyn AsyncWrite + Unpin + Send),
    ) -> Result<()> {
        self.read_through_channel(path, None, None, output).await?;
        output
            .flush()
            .await
            .map_err(|error| Error::io("flushing file output", error))
    }

    async fn write_from(
        &self,
        path: &str,
        input: &mut (dyn AsyncRead + Unpin + Send),
        length: u64,
    ) -> Result<()> {
        self.write_through_channel(path, input, length, false).await
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
        let mut file = tokio_fs::File::open(local)
            .await
            .map_err(|error| Error::io(format!("reading {}", local.display()), error))?;
        let length = file
            .metadata()
            .await
            .map_err(|error| Error::io(format!("reading metadata of {}", local.display()), error))?
            .len();
        self.write_from(remote, &mut file, length).await
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
        self.read_to(remote, &mut file).await
    }
}

#[cfg(test)]
mod tests {
    use std::future;
    use std::process::Stdio;

    use sandbox_driver::SandboxProvider;
    use tokio::task::yield_now;

    use super::*;
    use crate::channel;

    #[tokio::test]
    async fn cancellation_before_open_releases_local_admission() {
        let limits = TransportLimits {
            active_io: 1,
            hard_cancel_drain_timeout: Duration::from_millis(50),
            ..TransportLimits::default()
        };
        let (reader, _peer_writer) = duplex(4096);
        let (writer, _peer_reader) = duplex(4096);
        let listener =
            ChannelListener::bind_with_limits(limits.clone(), TrustedPeer::Process(process::id()))
                .expect("listener");
        let client = Client::start(reader, writer, listener, limits);
        let (_, receiver) = client.listener.expect().expect("admission");
        let kill = CancellationToken::new();
        kill.cancel();
        let result = time::timeout(
            Duration::from_secs(1),
            run_channel_exec(
                &client,
                m::EXEC_STREAM,
                &m::Empty,
                "before-open",
                receiver,
                None,
                &ExecControls {
                    kill: Some(kill),
                    ..ExecControls::default()
                },
            ),
        )
        .await
        .expect("deadline");
        assert!(matches!(result, Err(Error::Incomplete(_))));
        assert_eq!(client.listener.diagnostics().active_io, 0);
        assert!(client.listener.expect().is_ok());
        assert!(!client.closed.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn cancellation_after_result_bounds_output_and_partial_eof_delivery() {
        use tokio::io::split;
        use tokio::net::UnixStream;
        for partial_eof in [false, true] {
            let limits = TransportLimits {
                hard_cancel_drain_timeout: Duration::from_millis(100),
                ..TransportLimits::default()
            };
            let (host, peer_control) = duplex(4096);
            let (reader, writer) = split(host);
            let (peer_reader, mut peer_writer) = split(peer_control);
            let listener = ChannelListener::bind_with_limits(
                limits.clone(),
                TrustedPeer::Process(process::id()),
            )
            .expect("listener");
            let transport = listener.transport();
            let client = Client::start(reader, writer, listener, limits);
            let (request, receiver) = client.listener.expect().expect("admitted");
            let mut peer = UnixStream::connect(&transport.socket_path)
                .await
                .expect("socket");
            FrameWriter::new(&mut peer, transport.max_frame_bytes)
                .write(
                    FrameKind::Open,
                    &serde_json::to_vec(&request).expect("open"),
                )
                .await
                .expect("authenticate");
            if partial_eof {
                // A valid EOF kind with an incomplete length must never mean
                // complete output, even after a successful control response.
                peer.write_all(&[4, 0]).await.expect("partial EOF header");
            } else {
                FrameWriter::new(&mut peer, transport.max_frame_bytes)
                    .write(FrameKind::Stdout, b"pending output")
                    .await
                    .expect("output");
            }
            let kill = CancellationToken::new();
            let remote_kill = kill.clone();
            let response_task = AbortOnDropHandle::new(tokio::spawn(async move {
                let mut reader = BufReader::new(peer_reader);
                let mut partial = Vec::new();
                while let Some(line) = control::read_line(&mut reader, &mut partial, 4096)
                    .await
                    .expect("request")
                {
                    let request: Message = serde_json::from_slice(&line).expect("message");
                    let id = request.id.expect("id");
                    let response = if request.method.as_deref() == Some(m::EXEC_STREAM) {
                        let result = ExecStreamingResult::new(ExecResult::from_shell_status(
                            Termination::Exited,
                            Some(0),
                            Duration::ZERO,
                        ));
                        Message::response(
                            id,
                            serde_json::to_value(m::ExecStreamResult {
                                result:            m::ExecResultDto::from_result(&result.result),
                                live_streaming:    true,
                                streams_separated: true,
                                stdout_capture:    result.stdout_capture,
                                stderr_capture:    result.stderr_capture,
                            })
                            .expect("response"),
                        )
                    } else {
                        Message::response(id, Value::Null)
                    };
                    peer_writer
                        .write_all(
                            format!("{}\n", serde_json::to_string(&response).expect("encode"))
                                .as_bytes(),
                        )
                        .await
                        .expect("reply");
                    if request.method.as_deref() == Some(m::EXEC_STREAM) {
                        remote_kill.cancel();
                    }
                }
            }));
            let outcome = time::timeout(
                Duration::from_secs(2),
                run_channel_exec(
                    &client,
                    m::EXEC_STREAM,
                    &m::Empty,
                    "after-result",
                    receiver,
                    None,
                    &ExecControls {
                        kill: Some(kill),
                        sink: Some(Arc::new(|_, _| Box::pin(future::pending()))),
                        ..ExecControls::default()
                    },
                ),
            )
            .await
            .expect("local completion bounded");
            let Err(Error::Incomplete(outcome)) = outcome else {
                panic!("must report incomplete delivery");
            };
            assert!(outcome.output_abandoned);
            assert!(outcome.stop_acknowledged);
            assert!(outcome.termination_confirmed);
            assert!(!outcome.cleanup_confirmed);
            let _: m::Empty = client
                .call(m::PROVIDER_HEALTH, &m::Empty)
                .await
                .expect("unrelated response remains available");
            assert_eq!(client.listener.diagnostics().active_io, 0);
            drop(peer);
            drop(response_task);
        }
    }

    #[tokio::test]
    async fn cleanup_failure_retains_admission_without_closing_other_calls() {
        let limits = TransportLimits {
            active_io: 1,
            ..TransportLimits::default()
        };
        let (reader, _plugin_writer) = duplex(1024);
        let (writer, _plugin_reader) = duplex(1024);
        let listener =
            ChannelListener::bind_with_limits(limits.clone(), TrustedPeer::Process(process::id()))
                .expect("listener");
        let client = Client::start(reader, writer, listener, limits);
        let (_, receiver) = client.listener.expect().expect("admitted");
        client.own_cleanup(receiver.io_permit(), async {
            Err(Error::invalid_spec("cleanup", "failed"))
        });
        drop(receiver);
        time::timeout(Duration::from_secs(1), async {
            while client
                .failed_cleanup
                .lock()
                .expect("failed cleanup lock")
                .is_empty()
            {
                yield_now().await;
            }
        })
        .await
        .expect("cleanup failure recorded");
        assert!(!client.closed.load(Ordering::SeqCst));
        assert!(matches!(
            client.listener.expect(),
            Err(Error::Overloaded { .. })
        ));
        assert!(limits::acquire(&client.reserved, "reserved_requests").is_ok());
    }

    #[tokio::test]
    async fn hard_cancel_drain_does_not_wait_for_stop_acknowledgment() {
        let limits = TransportLimits {
            hard_cancel_drain_timeout: Duration::from_millis(50),
            ..TransportLimits::default()
        };
        let (reader, _plugin_writer) = duplex(1024);
        let (writer, _plugin_reader) = duplex(1024);
        let listener =
            ChannelListener::bind_with_limits(limits.clone(), TrustedPeer::Process(process::id()))
                .expect("listener");
        let transport = listener.transport();
        let client = Client::start(reader, writer, listener, limits);
        let (request, receiver) = client.listener.expect().expect("admitted");
        let peer = channel::open(&transport, &request)
            .await
            .expect("authenticated peer");
        let kill = CancellationToken::new();
        kill.cancel();
        let outcome = time::timeout(
            Duration::from_secs(1),
            run_channel_exec(
                &client,
                m::EXEC_STREAM,
                &m::Empty,
                "cancelled",
                receiver,
                None,
                &ExecControls {
                    kill: Some(kill),
                    ..ExecControls::default()
                },
            ),
        )
        .await
        .expect("local drain deadline");
        let Err(Error::Incomplete(outcome)) = outcome else {
            panic!("must report incomplete drain");
        };
        assert!(outcome.output_abandoned);
        assert!(!outcome.stop_acknowledged);
        assert!(!outcome.termination_confirmed);
        assert!(!outcome.cleanup_confirmed);
        assert!(!client.closed.load(Ordering::SeqCst));
        drop(peer);
    }

    #[tokio::test]
    async fn shutdown_kills_a_plugin_that_never_acknowledges() {
        let mut child = Command::new("sh")
            .args(["-c", "read request; exec sleep 300"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .expect("unresponsive plugin");
        let reader = child.stdout.take().expect("stdout");
        let writer = child.stdin.take().expect("stdin");
        let provider = PluginProvider {
            client:       Client::start(
                reader,
                writer,
                ChannelListener::bind().expect("bind"),
                TransportLimits::default(),
            ),
            kind:         ProviderKind::try_new("host").expect("kind"),
            capabilities: Capabilities::minimal(sandbox_driver::Isolation::None),
            snapshots:    None,
            volumes:      None,
            child:        Some(Mutex::new(Some(child))),
        };
        let error = time::timeout(SHUTDOWN_GRACE + Duration::from_secs(1), provider.shutdown())
            .await
            .expect("the missing acknowledgment is bounded")
            .expect_err("the plugin never acknowledged shutdown");
        assert!(matches!(error, Error::Transport(_)), "{error:?}");
        let result = time::timeout(
            Duration::from_secs(1),
            provider.list(&SandboxFilter::default()),
        )
        .await
        .expect("the terminated plugin closes its transport");
        assert!(result.is_err());
        assert!(
            provider
                .client
                .pending
                .lock()
                .expect("pending lock")
                .is_empty()
        );
    }

    #[tokio::test]
    async fn a_failed_pump_does_not_wait_for_the_control_response() {
        let accepted = AtomicBool::new(true);
        let outcome = time::timeout(
            Duration::from_secs(1),
            call_with_pump(
                future::pending::<Result<()>>(),
                async { Err::<(), _>(Error::invalid_spec("sink", "closed")) },
                &accepted,
                "test",
            ),
        )
        .await
        .expect("pump failure resolves promptly");
        assert!(matches!(outcome, Err(Error::InvalidSpec { .. })));
    }

    #[tokio::test]
    async fn cancelling_a_call_removes_its_pending_response() {
        let (reader, _plugin_writer) = duplex(1024);
        let (writer, _plugin_reader) = duplex(1024);
        let client = Client::start(
            reader,
            writer,
            ChannelListener::bind().expect("bind"),
            TransportLimits::default(),
        );
        let mut call = Box::pin(client.call::<_, m::Empty>("test", &m::Empty));
        tokio::select! {
            biased;
            result = &mut call => panic!("call must await a response: {result:?}"),
            () = yield_now() => {}
        }
        assert_eq!(client.pending.lock().expect("pending lock").len(), 1);
        drop(call);
        assert!(client.pending.lock().expect("pending lock").is_empty());
    }

    #[tokio::test]
    async fn dropping_the_client_releases_its_transport() {
        let (reader, _plugin_writer) = duplex(1024);
        let (writer, mut plugin_reader) = duplex(1024);
        let client = Client::start(
            reader,
            writer,
            ChannelListener::bind().expect("bind"),
            TransportLimits::default(),
        );
        let socket = client.listener.transport().socket_path;
        let weak = Arc::downgrade(&client);
        drop(client);
        assert!(
            weak.upgrade().is_none(),
            "transport tasks must not retain the client"
        );
        assert!(!tokio_fs::try_exists(socket).await.expect("socket lookup"));
        let mut byte = [0];
        assert_eq!(
            time::timeout(Duration::from_secs(1), plugin_reader.read(&mut byte))
                .await
                .expect("writer task closes")
                .expect("read"),
            0
        );
    }

    #[tokio::test]
    async fn abandoning_an_operation_drops_its_pump() {
        let (sender, mut receiver) = oneshot::channel::<()>();
        let accepted = AtomicBool::new(false);
        let pump = async move {
            let _sender = sender;
            future::pending::<Result<()>>().await
        };
        let mut operation = Box::pin(call_with_pump(
            future::pending::<Result<()>>(),
            pump,
            &accepted,
            "test",
        ));
        tokio::select! {
            biased;
            _ = &mut operation => panic!("operation must wait"),
            () = yield_now() => {}
        }
        assert!(matches!(
            receiver.try_recv(),
            Err(oneshot::error::TryRecvError::Empty)
        ));
        drop(operation);
        assert!(
            receiver.await.is_err(),
            "the pump releases its owned resources"
        );
    }
}
