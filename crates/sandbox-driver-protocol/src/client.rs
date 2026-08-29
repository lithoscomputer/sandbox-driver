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
    Capabilities, Capability, CheckpointId, CheckpointOptions, DirEntry, Error, EventCallback,
    Exec, ExecControls, ExecResult, ExecSpec, ExecStreamingResult, FileMetadata, Filesystem,
    ForkOptions, LifecycleTimers, NetworkPolicy, OutputSink, PlatformInfo, PreviewUrl, PreviewUrls,
    ProviderKind, Resources, Result, Sandbox, SandboxFilter, SandboxId, SandboxSnapshotOptions,
    SandboxSpec, SandboxStatus, SnapshotFilter, SnapshotId, SnapshotService, SnapshotSpec,
    SnapshotStatus, SpawnSpec, SshAccess, SshAccessInfo, StdioProcess, VolumeId, VolumeService,
    VolumeSpec, VolumeStatus,
};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::{mpsc, oneshot};
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
        let info: m::HandleInfo = self
            .client
            .call(m::SANDBOX_CREATE, &m::CreateParams { spec: spec.clone() })
            .await?;
        Ok(self.wrap_handle(info, events))
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

    async fn list(&self, filter: &SandboxFilter) -> Result<Vec<SandboxStatus>> {
        let result: m::ListResult = self
            .client
            .call(m::SANDBOX_LIST, &m::ListParams {
                filter: filter.clone(),
            })
            .await?;
        Ok(result.sandboxes)
    }

    fn snapshots(&self) -> Option<&dyn SnapshotService> {
        self.snapshots
            .as_ref()
            .map(|service| service as &dyn SnapshotService)
    }

    fn volumes(&self) -> Option<&dyn VolumeService> {
        self.volumes
            .as_ref()
            .map(|service| service as &dyn VolumeService)
    }
}

/// Snapshot service backed by the plugin.
struct ProviderSnapshots {
    client: Arc<Client>,
}

#[async_trait]
impl SnapshotService for ProviderSnapshots {
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
}

/// Volume service backed by the plugin.
struct ProviderVolumes {
    client: Arc<Client>,
}

#[async_trait]
impl VolumeService for ProviderVolumes {
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

/// Removes capabilities the protocol cannot yet deliver through the
/// wire, so the client never advertises what its adapters would then
/// refuse: long-lived stdio (needs the side-channel transport), PTY,
/// logs, native search/git passthrough, and the reserved access facets.
/// Snapshots, volumes, preview URLs, and SSH cross the wire and stay.
fn mask_wire_capabilities(capabilities: &mut Capabilities) {
    capabilities.exec.stdio_process = false;
    capabilities.pty = None;
    capabilities.logs = None;
    capabilities.search.native = false;
    capabilities.git.native = false;
    capabilities.access.shell_command = false;
    capabilities.access.web_terminal = false;
    capabilities.access.vnc = false;
    capabilities.access.vpn = false;
}

/// Request/response correlation plus notification routing.
struct Client {
    outbound:        mpsc::Sender<Message>,
    next_id:         AtomicU64,
    next_exec:       AtomicU64,
    /// Set when either transport task ends; every pending and future call
    /// fails fast instead of waiting on a dead pipe.
    closed:          AtomicBool,
    pending:         Mutex<HashMap<u64, oneshot::Sender<Result<Value>>>>,
    exec_sinks:      Mutex<HashMap<String, OutputSink>>,
    event_callbacks: Mutex<HashMap<String, EventCallback>>,
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
            closed: AtomicBool::new(false),
            pending: Mutex::new(HashMap::new()),
            exec_sinks: Mutex::new(HashMap::new()),
            event_callbacks: Mutex::new(HashMap::new()),
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
                let sink = self
                    .exec_sinks
                    .lock()
                    .expect("exec sinks lock")
                    .get(&notification.exec_id)
                    .cloned();
                if let (Some(sink), Ok(chunk)) = (sink, decode_bytes(&notification.data_b64)) {
                    let _ = sink(notification.stream, chunk).await;
                }
            }
            m::HOST_EVENT => {
                let Ok(notification) = serde_json::from_value::<m::HostEventNotification>(params)
                else {
                    return;
                };
                let callback = self
                    .event_callbacks
                    .lock()
                    .expect("event callbacks lock")
                    .get(&notification.sandbox_id)
                    .cloned();
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

/// A sandbox handle backed by the plugin.
struct SandboxHandle {
    client:            Arc<Client>,
    id:                SandboxId,
    capabilities:      Capabilities,
    working_directory: String,
    runtime_directory: Option<String>,
    exec:              SandboxExec,
    access:            SandboxAccess,
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
        if let Some(sink) = controls.sink.clone() {
            self.client
                .exec_sinks
                .lock()
                .expect("exec sinks lock")
                .insert(exec_id.clone(), sink);
        }
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
            .exec_sinks
            .lock()
            .expect("exec sinks lock")
            .remove(&exec_id);
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

    /// Deferred: the base64 side-channel transport for long-lived stdio
    /// is not in protocol v1.
    async fn spawn_stdio(&self, _spec: &SpawnSpec) -> Result<StdioProcess> {
        Err(Error::unsupported(Capability::ExecStdioProcess))
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
            .call(m::FS_READ, &self.path_params(path))
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
