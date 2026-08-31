//! Method names and parameter/result DTOs.
//!
//! Wire DTOs may share their serde shape with core domain types in v1;
//! their compatibility rules are verified by `tests/compat.rs`.
//! Byte payloads always cross as base64 strings. Divergence, when a shape
//! must evolve, is absorbed here — never by breaking core types.

use std::collections::BTreeMap;
use std::time::Duration;

use sandbox_driver::{
    Capabilities, CaptureStats, DirEntry, Error, ExecResult, ExecSpec, FileMetadata, ForkOptions,
    LifecycleTimers, LogSource, NetworkPolicy, OutputSanitization, PlatformInfo, ProviderKind,
    PtyOptions, PtySize, Resources, SandboxEvent, SandboxFilter, SandboxId, SandboxSnapshotOptions,
    SandboxSpec, SandboxStatus, SnapshotMode, SnapshotSource, SnapshotSpec, SpawnSpec, Termination,
    VncConnection,
};
use serde::{Deserialize, Serialize};

use crate::wire::{decode_bytes, encode_bytes};

/// Protocol version this crate speaks.
pub const PROTOCOL_VERSION: u32 = 1;

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
pub const EXEC_RUN: &str = "exec/run";
pub const EXEC_STREAM: &str = "exec/stream";
pub const EXEC_CANCEL: &str = "exec/cancel";
pub const EXEC_STDIO_OPEN: &str = "exec/stdio_open";
pub const EXEC_STDIO_INPUT: &str = "exec/stdio_input";
pub const EXEC_STDIO_CLOSE_INPUT: &str = "exec/stdio_close_input";
pub const EXEC_STDIO_OUTPUT: &str = "exec/stdio_output";
pub const EXEC_STDIO_TERMINATE: &str = "exec/stdio_terminate";
pub const EXEC_STDIO_WAIT: &str = "exec/stdio_wait";
pub const PTY_OPEN: &str = "pty/open";
pub const PTY_INPUT: &str = "pty/input";
pub const PTY_OUTPUT: &str = "pty/output";
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

pub const SNAPSHOT_CREATE: &str = "snapshot/create";
pub const SNAPSHOT_GET: &str = "snapshot/get";
pub const SNAPSHOT_LIST: &str = "snapshot/list";
pub const SNAPSHOT_DELETE: &str = "snapshot/delete";
pub const SNAPSHOT_ACTIVATE: &str = "snapshot/activate";
pub const SNAPSHOT_DEACTIVATE: &str = "snapshot/deactivate";
pub const SNAPSHOT_BUILD_LOGS: &str = "snapshot/build_logs";
pub const PROVIDER_HEALTH: &str = "provider/health";
pub const VOLUME_CREATE: &str = "volume/create";
pub const VOLUME_GET: &str = "volume/get";
pub const VOLUME_LIST: &str = "volume/list";
pub const VOLUME_DELETE: &str = "volume/delete";
pub const ACCESS_PREVIEW_URL: &str = "access/preview_url";
pub const ACCESS_SIGNED_PREVIEW_URL: &str = "access/signed_preview_url";
pub const ACCESS_SSH_CREATE: &str = "access/ssh_create";
pub const ACCESS_SSH_REVOKE: &str = "access/ssh_revoke";
pub const ACCESS_WEB_TERMINAL: &str = "access/web_terminal";
pub const ACCESS_VNC: &str = "access/vnc";

// Notifications, plugin → host.
pub const EXEC_OUTPUT: &str = "exec/output";
pub const HOST_EVENT: &str = "host/event";
pub const HOST_LOG: &str = "host/log";
pub const LOG_OUTPUT: &str = "logs/output";

#[derive(Debug, Serialize, Deserialize)]
pub struct InitializeParams {
    pub protocol_version: u32,
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
    pub spec:         SandboxSpec,
    /// Host-generated id correlating `host/event` notifications emitted
    /// while this create runs, before a sandbox id exists.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation_id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AttachParams {
    pub sandbox_id: String,
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

/// [`ExecSpec`] with the stdin payload in base64.
#[derive(Debug, Serialize, Deserialize)]
pub struct ExecSpecDto {
    pub command:             String,
    pub timeout_ms:          Option<u64>,
    pub working_dir:         Option<String>,
    pub env:                 BTreeMap<String, String>,
    pub stdin_b64:           Option<String>,
    #[serde(default, skip_serializing_if = "output_sanitization_is_raw")]
    pub output_sanitization: OutputSanitization,
}

impl ExecSpecDto {
    pub fn from_spec(spec: &ExecSpec) -> Self {
        Self {
            command:             spec.command.clone(),
            timeout_ms:          spec
                .timeout
                .map(|timeout| u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX)),
            working_dir:         spec.working_dir.clone(),
            env:                 spec.env.clone(),
            stdin_b64:           spec.stdin.as_deref().map(encode_bytes),
            output_sanitization: spec.output_sanitization,
        }
    }

    pub fn into_spec(self) -> Result<ExecSpec, sandbox_driver::Error> {
        let mut spec = ExecSpec::new(self.command);
        if let Some(timeout_ms) = self.timeout_ms {
            spec = spec.timeout(Duration::from_millis(timeout_ms));
        }
        if let Some(dir) = self.working_dir {
            spec = spec.working_dir(dir);
        }
        for (key, value) in self.env {
            spec = spec.env_var(key, value);
        }
        if let Some(stdin) = self.stdin_b64 {
            spec = spec.stdin(decode_bytes(&stdin)?);
        }
        spec = spec.output_sanitization(self.output_sanitization);
        Ok(spec)
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

#[derive(Debug, Serialize, Deserialize)]
pub struct ExecRunParams {
    pub sandbox_id: String,
    pub spec:       ExecSpecDto,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ExecResultDto {
    pub stdout_b64:  String,
    pub stderr_b64:  String,
    pub exit_code:   Option<i32>,
    pub termination: Termination,
    pub duration_ms: u64,
}

impl ExecResultDto {
    pub fn from_result(result: &ExecResult) -> Self {
        Self {
            stdout_b64:  encode_bytes(&result.stdout),
            stderr_b64:  encode_bytes(&result.stderr),
            exit_code:   result.exit_code,
            termination: result.termination,
            duration_ms: u64::try_from(result.duration.as_millis()).unwrap_or(u64::MAX),
        }
    }

    pub fn into_result(self) -> Result<ExecResult, sandbox_driver::Error> {
        let mut result = ExecResult::new(
            self.termination,
            self.exit_code,
            Duration::from_millis(self.duration_ms),
        );
        result.stdout = decode_bytes(&self.stdout_b64)?;
        result.stderr = decode_bytes(&self.stderr_b64)?;
        Ok(result)
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ExecStreamParams {
    pub sandbox_id:            String,
    /// Client-generated, routes `exec/output` notifications and
    /// `exec/cancel` before the response arrives.
    pub exec_id:               String,
    pub spec:                  ExecSpecDto,
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
pub struct ExecOutputNotification {
    pub exec_id:  String,
    pub stream:   sandbox_driver::OutputStream,
    pub data_b64: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ExecCancelParams {
    pub exec_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct StdioOpenParams {
    pub sandbox_id: String,
    pub process_id: String,
    pub spec:       SpawnSpec,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct StdioIdParams {
    pub process_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct StdioInputParams {
    pub process_id: String,
    pub data_b64:   String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct StdioOutputResult {
    pub data_b64: Option<String>,
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
    pub options:    PtyOptions,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PtyIdParams {
    pub pty_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PtyInputParams {
    pub pty_id:   String,
    pub data_b64: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PtyOutputResult {
    pub data_b64: Option<String>,
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
    pub source:     LogSource,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct StreamIdParams {
    pub stream_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LogOutputNotification {
    pub stream_id: String,
    pub data_b64:  String,
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
    /// Byte offset to start reading at; whole-file read when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offset:     Option<u64>,
    /// Maximum bytes to read; to end of file when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub length:     Option<u64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FsReadResult {
    pub content_b64: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FsWriteParams {
    pub sandbox_id:  String,
    pub path:        String,
    pub content_b64: String,
    /// Append instead of truncating, for chunked uploads.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub append:      bool,
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

#[derive(Debug, Serialize, Deserialize)]
pub struct HostEventNotification {
    pub sandbox_id:   String,
    pub event:        SandboxEvent,
    /// Correlates the event to the long-running request that caused it,
    /// when the host supplied an `operation_id`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation_id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HostLogNotification {
    pub level:   String,
    pub message: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SnapshotCreateParams {
    pub spec: SnapshotSpecDto,
}

/// Protocol-v1 snapshot creation shape.
#[derive(Debug, Serialize, Deserialize)]
pub struct SnapshotSpecDto {
    #[serde(default)]
    pub name:            Option<String>,
    pub source:          SnapshotSourceDto,
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
        result.resources = spec.resources;
        result.provider_config = spec.provider_config;
        result
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SnapshotIdParams {
    pub snapshot_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SnapshotIdResult {
    pub snapshot_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SnapshotBuildLogsParams {
    pub snapshot_id: String,
    pub stream_id:   String,
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
    pub spec: sandbox_driver::VolumeSpec,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VolumeIdParams {
    pub volume_id: String,
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
