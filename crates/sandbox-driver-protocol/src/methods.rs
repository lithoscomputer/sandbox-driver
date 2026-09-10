//! Method names and parameter/result DTOs.
//!
//! Wire DTOs may share their serde shape with core domain types; their
//! compatibility rules are verified by `tests/compat.rs`. Byte payloads
//! never cross as JSON: every byte stream rides a data channel
//! ([`crate::channel`]) named by a [`ChannelRequest`] in the request that
//! needs it. Divergence, when a shape must evolve, is absorbed here —
//! never by breaking core types.

use std::collections::BTreeMap;
use std::fmt;
use std::time::Duration;

use sandbox_driver::{
    Capabilities, CaptureStats, CorrelationId, DirEntry, Error, Event, ExecResult, ExecSpec,
    FileMetadata, ForkOptions, GitCloneOptions, LifecycleTimers, LogSource, NetworkPolicy,
    OneShotSpec, OutputSanitization, PlatformInfo, ProviderKind, PtyOptions, PtySize, Resources,
    SandboxFilter, SandboxId, SandboxKind, SandboxSnapshotOptions, SandboxSource, SandboxSpec,
    SandboxStatus, SnapshotId, SnapshotMode, SnapshotSource, SnapshotSpec, SpawnSpec, StopLevel,
    Termination, VncConnection, VolumeMount,
};
use serde::{Deserialize, Serialize};

pub use crate::channel::{ChannelRequest, DataTransport};

/// Protocol version this crate speaks.
pub const PROTOCOL_VERSION: u32 = 2;

// Method names, host → plugin.
pub const INITIALIZE: &str = "initialize";
pub const SHUTDOWN: &str = "shutdown";
pub const SANDBOX_CREATE: &str = "sandbox/create";
pub const SANDBOX_ATTACH: &str = "sandbox/attach";
pub const SANDBOX_LIST: &str = "sandbox/list";
pub const SANDBOX_DESCRIBE: &str = "sandbox/describe";
pub const SANDBOX_PLATFORM_INFO: &str = "sandbox/platform_info";
pub const SANDBOX_START: &str = "sandbox/start";
pub const SANDBOX_STOP: &str = "sandbox/stop";
pub const SANDBOX_DELETE: &str = "sandbox/delete";
pub const SANDBOX_PAUSE: &str = "sandbox/pause";
pub const SANDBOX_RESUME: &str = "sandbox/resume";
pub const SANDBOX_ARCHIVE: &str = "sandbox/archive";
pub const SANDBOX_RECOVER: &str = "sandbox/recover";
pub const SANDBOX_UNDELETE: &str = "sandbox/undelete";
pub const SANDBOX_REFRESH_ACTIVITY: &str = "sandbox/refresh_activity";
pub const SANDBOX_FORK: &str = "sandbox/fork";
pub const SANDBOX_CHECKPOINT: &str = "sandbox/checkpoint";
pub const SANDBOX_RESTORE_CHECKPOINT: &str = "sandbox/restore_checkpoint";
pub const SANDBOX_RESIZE: &str = "sandbox/resize";
pub const SANDBOX_SNAPSHOT: &str = "sandbox/snapshot";
pub const SANDBOX_SET_TIMERS: &str = "sandbox/set_timers";
pub const SANDBOX_SET_LABELS: &str = "sandbox/set_labels";
pub const SANDBOX_UPDATE_NETWORK: &str = "sandbox/update_network";
pub const SANDBOX_ENVIRONMENT: &str = "sandbox/environment";
pub const EXEC_STREAM: &str = "exec/stream";
pub const EXEC_STOP: &str = "exec/stop";
pub const EXEC_STDIO_OPEN: &str = "exec/stdio_open";
pub const EXEC_STDIO_TERMINATE: &str = "exec/stdio_terminate";
pub const EXEC_STDIO_WAIT: &str = "exec/stdio_wait";
pub const ONE_SHOT_RUN: &str = "one_shot/run";
pub const PTY_OPEN: &str = "pty/open";
pub const PTY_RESIZE: &str = "pty/resize";
pub const PTY_CLOSE: &str = "pty/close";
pub const LOGS_FOLLOW: &str = "logs/follow";
pub const STREAM_CANCEL: &str = "stream/cancel";
pub const FS_READ: &str = "fs/read";
pub const FS_WRITE: &str = "fs/write";
pub const FS_DELETE: &str = "fs/delete";
pub const FS_EXISTS: &str = "fs/exists";
pub const FS_METADATA: &str = "fs/metadata";
pub const FS_LIST_DIR: &str = "fs/list_dir";
pub const FS_CREATE_DIR: &str = "fs/create_dir";
pub const FS_RENAME: &str = "fs/rename";
pub const FS_SET_PERMISSIONS: &str = "fs/set_permissions";
pub const GIT_CLONE: &str = "git/clone";

pub const SNAPSHOT_CREATE: &str = "snapshot/create";
pub const SNAPSHOT_GET: &str = "snapshot/get";
pub const SNAPSHOT_LIST: &str = "snapshot/list";
pub const SNAPSHOT_DELETE: &str = "snapshot/delete";
pub const SNAPSHOT_ACTIVATE: &str = "snapshot/activate";
pub const SNAPSHOT_DEACTIVATE: &str = "snapshot/deactivate";
pub const SNAPSHOT_BUILD_LOGS: &str = "snapshot/build_logs";
pub const TRANSPORT_DIAGNOSTICS: &str = "transport/diagnostics";
pub const PROVIDER_HEALTH: &str = "provider/health";
pub const VOLUME_CREATE: &str = "volume/create";
pub const VOLUME_GET: &str = "volume/get";
pub const VOLUME_LIST: &str = "volume/list";
pub const VOLUME_DELETE: &str = "volume/delete";
pub const ACCESS_PREVIEW_URL: &str = "access/preview_url";
pub const ACCESS_SIGNED_PREVIEW_URL: &str = "access/signed_preview_url";
pub const ACCESS_PREVIEW_RELEASE: &str = "access/preview_release";
pub const ACCESS_SSH_CREATE: &str = "access/ssh_create";
pub const ACCESS_SSH_REVOKE: &str = "access/ssh_revoke";
pub const ACCESS_WEB_TERMINAL: &str = "access/web_terminal";
pub const ACCESS_VNC: &str = "access/vnc";

// Notifications, plugin → host.
pub const HOST_EVENT: &str = "host/event";
pub const HOST_LOG: &str = "host/log";

#[derive(Debug, Serialize, Deserialize)]
pub struct InitializeParams {
    pub protocol_version: u32,
    /// Where the plugin opens its data channels. Required in version 2.
    pub data_transport:   DataTransport,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct InitializeResult {
    pub protocol_version: u32,
    pub provider:         ProviderInfo,
    pub capabilities:     Capabilities,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProviderInfo {
    pub kind:    ProviderKind,
    pub version: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateParams {
    pub spec:   SandboxSpecDto,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub events: Option<EventRequest>,
}

/// Routes an event stream back to the requesting host observer.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EventRequest {
    pub route_id:       String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub correlation_id: Option<CorrelationId>,
}

/// Protocol-v1 sandbox creation shape. Snapshot sources retain the
/// original `name` field even though the public API uses a typed id.
#[derive(Debug, Serialize, Deserialize)]
pub struct SandboxSpecDto {
    #[serde(default)]
    pub name:                Option<String>,
    pub source:              SandboxSourceDto,
    #[serde(default)]
    pub resources:           Resources,
    #[serde(default)]
    pub sandbox_kind:        Option<SandboxKind>,
    #[serde(default)]
    pub env:                 BTreeMap<String, String>,
    #[serde(default)]
    pub labels:              BTreeMap<String, String>,
    #[serde(default)]
    pub user:                Option<String>,
    #[serde(default)]
    pub working_directory:   Option<String>,
    #[serde(default)]
    pub workspace_ownership: Option<sandbox_driver::WorkspaceOwnership>,
    #[serde(default)]
    pub network:             NetworkPolicy,
    #[serde(default)]
    pub volumes:             Vec<VolumeMount>,
    #[serde(default)]
    pub timers:              LifecycleTimers,
    #[serde(default)]
    pub ephemeral:           bool,
    #[serde(default)]
    pub public:              Option<bool>,
    #[serde(default)]
    pub region:              Option<String>,
    #[serde(default)]
    pub provider_config:     serde_json::Value,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SandboxSourceDto {
    Image { reference: String },
    Dockerfile { content: String },
    Snapshot { name: String },
    HostDirectory,
}

impl TryFrom<&SandboxSpec> for SandboxSpecDto {
    type Error = Error;

    fn try_from(spec: &SandboxSpec) -> Result<Self, Self::Error> {
        let source = match &spec.source {
            SandboxSource::Image { reference } => SandboxSourceDto::Image {
                reference: reference.clone(),
            },
            SandboxSource::Dockerfile { content } => SandboxSourceDto::Dockerfile {
                content: content.clone(),
            },
            SandboxSource::Snapshot { id } => SandboxSourceDto::Snapshot {
                name: id.as_str().to_owned(),
            },
            SandboxSource::HostDirectory => SandboxSourceDto::HostDirectory,
            _ => return Err(Error::invalid_spec("source", "unsupported sandbox source")),
        };
        Ok(Self {
            name: spec.name.clone(),
            source,
            resources: spec.resources,
            sandbox_kind: spec.sandbox_kind,
            env: spec.env.clone(),
            labels: spec.labels.clone(),
            user: spec.user.clone(),
            working_directory: spec.working_directory.clone(),
            workspace_ownership: spec.workspace_ownership,
            network: spec.network.clone(),
            volumes: spec.volumes.clone(),
            timers: spec.timers,
            ephemeral: spec.ephemeral,
            public: spec.public,
            region: spec.region.clone(),
            provider_config: spec.provider_config.clone(),
        })
    }
}

impl TryFrom<SandboxSpecDto> for SandboxSpec {
    type Error = Error;

    fn try_from(spec: SandboxSpecDto) -> Result<Self, Self::Error> {
        let source = match spec.source {
            SandboxSourceDto::Image { reference } => SandboxSource::Image { reference },
            SandboxSourceDto::Dockerfile { content } => SandboxSource::Dockerfile { content },
            SandboxSourceDto::Snapshot { name } => SandboxSource::Snapshot {
                id: SnapshotId::try_new(name).map_err(|error| {
                    Error::invalid_spec("source.snapshot.name", error.to_string())
                })?,
            },
            SandboxSourceDto::HostDirectory => SandboxSource::HostDirectory,
        };
        let mut result = Self::new(source);
        result.name = spec.name;
        result.resources = spec.resources;
        result.sandbox_kind = spec.sandbox_kind;
        result.env = spec.env;
        result.labels = spec.labels;
        result.user = spec.user;
        result.working_directory = spec.working_directory;
        result.workspace_ownership = spec.workspace_ownership;
        result.network = spec.network;
        result.volumes = spec.volumes;
        result.timers = spec.timers;
        result.ephemeral = spec.ephemeral;
        result.public = spec.public;
        result.region = spec.region;
        result.provider_config = spec.provider_config;
        Ok(result)
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AttachParams {
    pub sandbox_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub events:     Option<EventRequest>,
}

/// Everything a client needs to build a remote sandbox handle.
#[derive(Debug, Serialize, Deserialize)]
pub struct HandleInfo {
    pub status:            SandboxStatus,
    pub capabilities:      Capabilities,
    pub working_directory: String,
    pub runtime_directory: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ListParams {
    pub filter: SandboxFilter,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ListResult {
    pub sandboxes: Vec<SandboxStatus>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SandboxIdParams {
    pub sandbox_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct StatusResult {
    pub status: SandboxStatus,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PlatformInfoResult {
    pub platform: PlatformInfo,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ForkParams {
    pub sandbox_id: String,
    pub options:    ForkOptionsDto,
}

/// Protocol-v1 fork options. The public API no longer makes memory
/// optional, so new callers always send `include_memory: true`.
#[derive(Debug, Serialize, Deserialize)]
pub struct ForkOptionsDto {
    #[serde(default)]
    pub name:           Option<String>,
    #[serde(default)]
    pub include_memory: bool,
}

impl From<&ForkOptions> for ForkOptionsDto {
    fn from(options: &ForkOptions) -> Self {
        Self {
            name:           options.name.clone(),
            include_memory: true,
        }
    }
}

impl TryFrom<ForkOptionsDto> for ForkOptions {
    type Error = Error;

    fn try_from(options: ForkOptionsDto) -> Result<Self, Self::Error> {
        if !options.include_memory {
            return Err(Error::invalid_spec(
                "include_memory",
                "fork must preserve memory and running processes",
            ));
        }
        let mut result = Self::default();
        result.name = options.name;
        Ok(result)
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ResizeParams {
    pub sandbox_id: String,
    pub resources:  Resources,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SnapshotParams {
    pub sandbox_id: String,
    pub options:    SandboxSnapshotOptionsDto,
}

/// Protocol-v1 snapshot options. `include_memory` maps to the normalized
/// snapshot mode.
#[derive(Debug, Serialize, Deserialize)]
pub struct SandboxSnapshotOptionsDto {
    #[serde(default)]
    pub name:           Option<String>,
    #[serde(default)]
    pub include_memory: bool,
}

impl From<&SandboxSnapshotOptions> for SandboxSnapshotOptionsDto {
    fn from(options: &SandboxSnapshotOptions) -> Self {
        Self {
            name:           options.name.clone(),
            include_memory: options.mode == SnapshotMode::LiveProcessState,
        }
    }
}

impl From<SandboxSnapshotOptionsDto> for SandboxSnapshotOptions {
    fn from(options: SandboxSnapshotOptionsDto) -> Self {
        let mut result = Self::default();
        result.name = options.name;
        result.mode = if options.include_memory {
            SnapshotMode::LiveProcessState
        } else {
            SnapshotMode::Filesystem
        };
        result
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SnapshotResult {
    pub snapshot_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SetTimersParams {
    pub sandbox_id: String,
    pub timers:     LifecycleTimers,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SetLabelsParams {
    pub sandbox_id: String,
    pub labels:     BTreeMap<String, String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UpdateNetworkParams {
    pub sandbox_id: String,
    pub network:    NetworkPolicy,
}

/// [`ExecSpec`] without its stdin: fixed and streamed stdin alike cross
/// as `Stdin` frames on the exec's data channel.
#[derive(Debug, Serialize, Deserialize)]
pub struct ExecSpecDto {
    pub program:             String,
    #[serde(default)]
    pub args:                Vec<String>,
    pub timeout_ms:          Option<u64>,
    /// Additive: absent from and ignored by peers built before it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stop_grace_ms:       Option<u64>,
    pub working_dir:         Option<String>,
    pub env:                 BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "output_sanitization_is_raw")]
    pub output_sanitization: OutputSanitization,
}

impl ExecSpecDto {
    pub fn from_spec(spec: &ExecSpec) -> Self {
        Self {
            program:             spec.program.clone(),
            args:                spec.args.clone(),
            timeout_ms:          spec
                .timeout
                .map(|timeout| u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX)),
            stop_grace_ms:       spec
                .stop_grace
                .map(|grace| u64::try_from(grace.as_millis()).unwrap_or(u64::MAX)),
            working_dir:         spec.working_dir.clone(),
            env:                 spec.env.clone(),
            output_sanitization: spec.output_sanitization,
        }
    }

    pub fn into_spec(self) -> ExecSpec {
        let mut spec = ExecSpec::new(self.program).args(self.args);
        // Wire semantics are authoritative: an absent timeout means
        // unbounded, so the constructor's default must not leak in.
        spec.timeout = self.timeout_ms.map(Duration::from_millis);
        spec.stop_grace = self.stop_grace_ms.map(Duration::from_millis);
        if let Some(dir) = self.working_dir {
            spec = spec.working_dir(dir);
        }
        for (key, value) in self.env {
            spec = spec.env_var(key, value);
        }
        spec.output_sanitization(self.output_sanitization)
    }
}

// serde's `skip_serializing_if` callback receives a reference even for a
// one-byte Copy enum.
#[allow(
    clippy::trivially_copy_pass_by_ref,
    reason = "serde skip_serializing_if requires a reference callback"
)]
fn output_sanitization_is_raw(value: &OutputSanitization) -> bool {
    *value == OutputSanitization::Raw
}

/// The metadata of a finished exec. Its bytes went over the channel: the
/// host keeps its own retained copy, bounded by the limit it asked for,
/// and the accounting here is the plugin's.
#[derive(Debug, Serialize, Deserialize)]
pub struct ExecResultDto {
    pub exit_code:   Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signal:      Option<i32>,
    pub termination: Termination,
    pub duration_ms: u64,
}

impl ExecResultDto {
    pub fn from_result(result: &ExecResult) -> Self {
        Self {
            exit_code:   result.exit_code,
            signal:      result.signal,
            termination: result.termination,
            duration_ms: u64::try_from(result.duration.as_millis()).unwrap_or(u64::MAX),
        }
    }

    /// The result with `stdout` and `stderr` as the host retained them.
    pub fn into_result(self, stdout: Vec<u8>, stderr: Vec<u8>) -> ExecResult {
        let mut result = ExecResult::new(
            self.termination,
            self.exit_code,
            Duration::from_millis(self.duration_ms),
        );
        result.signal = self.signal;
        result.stdout = stdout;
        result.stderr = stderr;
        result
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ExecStreamParams {
    pub sandbox_id:            String,
    /// Client-generated: routes `exec/stop` before the response arrives.
    pub exec_id:               String,
    pub channel:               ChannelRequest,
    pub spec:                  ExecSpecDto,
    /// The command reads its standard input from the channel's `Stdin`
    /// frames. When false the plugin gives it end-of-file at once.
    #[serde(default)]
    pub stdin:                 bool,
    pub retained_output_limit: Option<usize>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ExecStreamResult {
    pub result:            ExecResultDto,
    pub streams_separated: bool,
    pub live_streaming:    bool,
    pub stdout_capture:    CaptureStats,
    pub stderr_capture:    CaptureStats,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ExecStopParams {
    pub exec_id: String,
    /// `term` or `kill`.
    pub level:   StopLevel,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OneShotRunParams {
    pub sandbox_id:            String,
    /// Client-generated: routes `exec/stop` before the response arrives.
    pub exec_id:               String,
    pub channel:               ChannelRequest,
    pub spec:                  OneShotSpec,
    pub retained_output_limit: Option<usize>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct StdioOpenParams {
    pub sandbox_id: String,
    pub process_id: String,
    /// Stdin travels host to plugin, stdout plugin to host.
    pub channel:    ChannelRequest,
    pub spec:       SpawnSpec,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct StdioIdParams {
    pub process_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct StdioWaitResult {
    pub termination: Termination,
    pub exit_code:   Option<i32>,
    pub stderr_tail: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PtyOpenParams {
    pub sandbox_id: String,
    pub pty_id:     String,
    /// Input travels host to plugin, output plugin to host.
    pub channel:    ChannelRequest,
    pub options:    PtyOptions,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PtyIdParams {
    pub pty_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PtyResizeParams {
    pub pty_id: String,
    pub size:   PtySize,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LogsFollowParams {
    pub sandbox_id: String,
    pub stream_id:  String,
    pub channel:    ChannelRequest,
    pub source:     LogSource,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct StreamIdParams {
    pub stream_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FsPathParams {
    pub sandbox_id: String,
    pub path:       String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FsReadParams {
    pub sandbox_id: String,
    pub path:       String,
    /// The file's bytes arrive as `Stdout` frames.
    pub channel:    ChannelRequest,
    /// Byte offset to start reading at; whole-file read when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offset:     Option<u64>,
    /// Maximum bytes to read; to end of file when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub length:     Option<u64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FsWriteParams {
    pub sandbox_id:     String,
    pub path:           String,
    /// The content arrives as `Stdin` frames, ended by the host's `Eof`.
    pub channel:        ChannelRequest,
    /// Append instead of truncating.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub append:         bool,
    /// Exact byte count, allowing providers to stream an overwrite without
    /// collecting the channel first. Absent on earlier version 2 requests.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_length: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EnvironmentResult {
    pub environment: BTreeMap<String, String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FsDeleteParams {
    pub sandbox_id: String,
    pub path:       String,
    pub recursive:  bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FsExistsResult {
    pub exists: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FsMetadataResult {
    pub metadata: FileMetadata,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FsListDirParams {
    pub sandbox_id: String,
    pub path:       String,
    pub depth:      usize,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FsListDirResult {
    pub entries: Vec<DirEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FsRenameParams {
    pub sandbox_id: String,
    pub from:       String,
    pub to:         String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FsSetPermissionsParams {
    pub sandbox_id: String,
    pub path:       String,
    pub mode:       u32,
}

/// A repository clone the plugin runs with the provider's own git
/// implementation (native, derived, or hybrid), so a host sees the same
/// clone whether the provider is in-process or a plugin. The remaining
/// git operations stay exec-derived on the host side.
///
/// `Debug` redacts the URL, which can embed credentials, and relies on
/// [`GitCloneOptions`] to redact the credential password.
#[derive(Serialize, Deserialize)]
pub struct GitCloneParams {
    pub sandbox_id:  String,
    pub url:         String,
    pub target_path: String,
    #[serde(default)]
    pub options:     GitCloneOptions,
}

impl fmt::Debug for GitCloneParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GitCloneParams")
            .field("sandbox_id", &self.sandbox_id)
            .field("url", &"<redacted>")
            .field("target_path", &self.target_path)
            .field("options", &self.options)
            .finish()
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HostEventNotification {
    pub event:    Event,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route_id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HostLogNotification {
    pub level:   String,
    pub message: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SnapshotCreateParams {
    pub spec:   SnapshotSpecDto,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub events: Option<EventRequest>,
}

/// Protocol-v1 snapshot creation shape.
#[derive(Debug, Serialize, Deserialize)]
pub struct SnapshotSpecDto {
    #[serde(default)]
    pub name:            Option<String>,
    pub source:          SnapshotSourceDto,
    #[serde(default)]
    pub sandbox_kind:    Option<SandboxKind>,
    #[serde(default)]
    pub region:          Option<String>,
    #[serde(default)]
    pub resources:       Resources,
    #[serde(default)]
    pub provider_config: serde_json::Value,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotSourceDto {
    Image {
        reference: String,
    },
    Dockerfile {
        content: String,
    },
    Sandbox {
        id:             SandboxId,
        #[serde(default)]
        include_memory: bool,
    },
}

impl TryFrom<&SnapshotSpec> for SnapshotSpecDto {
    type Error = Error;

    fn try_from(spec: &SnapshotSpec) -> Result<Self, Self::Error> {
        let source = match &spec.source {
            SnapshotSource::Image { reference } => SnapshotSourceDto::Image {
                reference: reference.clone(),
            },
            SnapshotSource::Dockerfile { content } => SnapshotSourceDto::Dockerfile {
                content: content.clone(),
            },
            SnapshotSource::Sandbox { id, mode } => SnapshotSourceDto::Sandbox {
                id:             id.clone(),
                include_memory: *mode == SnapshotMode::LiveProcessState,
            },
            _ => return Err(Error::invalid_spec("source", "unsupported snapshot source")),
        };
        Ok(Self {
            name: spec.name.clone(),
            source,
            sandbox_kind: spec.sandbox_kind,
            region: spec.region.clone(),
            resources: spec.resources,
            provider_config: spec.provider_config.clone(),
        })
    }
}

impl From<SnapshotSpecDto> for SnapshotSpec {
    fn from(spec: SnapshotSpecDto) -> Self {
        let source = match spec.source {
            SnapshotSourceDto::Image { reference } => SnapshotSource::Image { reference },
            SnapshotSourceDto::Dockerfile { content } => SnapshotSource::Dockerfile { content },
            SnapshotSourceDto::Sandbox { id, include_memory } => SnapshotSource::Sandbox {
                id,
                mode: if include_memory {
                    SnapshotMode::LiveProcessState
                } else {
                    SnapshotMode::Filesystem
                },
            },
        };
        let mut result = Self::new(source);
        result.name = spec.name;
        result.sandbox_kind = spec.sandbox_kind;
        result.region = spec.region;
        result.resources = spec.resources;
        result.provider_config = spec.provider_config;
        result
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SnapshotIdParams {
    pub snapshot_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub events:      Option<EventRequest>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SnapshotIdResult {
    pub snapshot_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SnapshotBuildLogsParams {
    pub snapshot_id: String,
    pub stream_id:   String,
    pub channel:     ChannelRequest,
    pub follow:      bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SnapshotStatusResult {
    pub status: sandbox_driver::SnapshotStatus,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SnapshotListParams {
    pub filter: sandbox_driver::SnapshotFilter,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SnapshotListResult {
    pub snapshots: Vec<sandbox_driver::SnapshotStatus>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VolumeCreateParams {
    pub spec:   sandbox_driver::VolumeSpec,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub events: Option<EventRequest>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VolumeIdParams {
    pub volume_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub events:    Option<EventRequest>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VolumeIdResult {
    pub volume_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VolumeStatusResult {
    pub status: sandbox_driver::VolumeStatus,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VolumeListResult {
    pub volumes: Vec<sandbox_driver::VolumeStatus>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PreviewUrlParams {
    pub sandbox_id: String,
    pub port:       u16,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SignedPreviewUrlParams {
    pub sandbox_id:    String,
    pub port:          u16,
    pub expires_in_ms: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PreviewUrlResult {
    pub preview: sandbox_driver::PreviewUrl,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SshCreateParams {
    pub sandbox_id: String,
    pub ttl_ms:     Option<u64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SshCreateResult {
    pub access: sandbox_driver::SshAccessInfo,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SshRevokeParams {
    pub sandbox_id: String,
    pub token:      String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WebTerminalResult {
    pub url: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VncResult {
    pub connection: VncConnection,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HealthResult {
    pub health: sandbox_driver::ProviderHealth,
}

/// Empty result for side-effect-only methods.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Empty;
