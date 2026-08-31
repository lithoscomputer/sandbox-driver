//! Method names and parameter/result DTOs.
//!
//! Wire DTOs may share their serde shape with core domain types in v1;
//! those shapes are pinned by the golden-file tests in `tests/golden.rs`.
//! Byte payloads always cross as base64 strings. Divergence, when a shape
//! must evolve, is absorbed here — never by breaking core types.

use std::collections::BTreeMap;
use std::time::Duration;

use sandbox_driver::{
    Capabilities, CaptureStats, CheckpointOptions, DirEntry, ExecResult, ExecSpec, FileMetadata,
    ForkOptions, LifecycleTimers, NetworkPolicy, PlatformInfo, ProviderKind, Resources,
    SandboxEvent, SandboxFilter, SandboxSnapshotOptions, SandboxSpec, SandboxStatus, Termination,
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
pub const PROVIDER_HEALTH: &str = "provider/health";
pub const VOLUME_CREATE: &str = "volume/create";
pub const VOLUME_GET: &str = "volume/get";
pub const VOLUME_LIST: &str = "volume/list";
pub const VOLUME_DELETE: &str = "volume/delete";
pub const ACCESS_PREVIEW_URL: &str = "access/preview_url";
pub const ACCESS_SIGNED_PREVIEW_URL: &str = "access/signed_preview_url";
pub const ACCESS_SSH_CREATE: &str = "access/ssh_create";
pub const ACCESS_SSH_REVOKE: &str = "access/ssh_revoke";

// Notifications, plugin → host.
pub const EXEC_OUTPUT: &str = "exec/output";
pub const HOST_EVENT: &str = "host/event";
pub const HOST_LOG: &str = "host/log";

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
    pub options:    ForkOptions,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CheckpointParams {
    pub sandbox_id: String,
    pub options:    CheckpointOptions,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CheckpointResult {
    pub checkpoint_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RestoreCheckpointParams {
    pub sandbox_id:    String,
    pub checkpoint_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ResizeParams {
    pub sandbox_id: String,
    pub resources:  Resources,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SnapshotParams {
    pub sandbox_id: String,
    pub options:    SandboxSnapshotOptions,
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
    pub command:     String,
    pub timeout_ms:  Option<u64>,
    pub working_dir: Option<String>,
    pub env:         BTreeMap<String, String>,
    pub stdin_b64:   Option<String>,
}

impl ExecSpecDto {
    pub fn from_spec(spec: &ExecSpec) -> Self {
        Self {
            command:     spec.command.clone(),
            timeout_ms:  spec
                .timeout
                .map(|timeout| u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX)),
            working_dir: spec.working_dir.clone(),
            env:         spec.env.clone(),
            stdin_b64:   spec.stdin.as_deref().map(encode_bytes),
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
        Ok(spec)
    }
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
    pub spec: sandbox_driver::SnapshotSpec,
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
pub struct HealthResult {
    pub health: sandbox_driver::ProviderHealth,
}

/// Empty result for side-effect-only methods.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Empty;
