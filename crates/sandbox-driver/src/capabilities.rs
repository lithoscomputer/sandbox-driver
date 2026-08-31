use std::fmt;

use serde::{Deserialize, Serialize};

/// Isolation level a provider declares for its sandboxes. Never assumed.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Isolation {
    /// No isolation: commands run with the caller's own permissions (Host).
    None,
    /// Kernel-sharing container isolation (Docker).
    Container,
    /// Hardware-virtualized isolation (Daytona, boxd).
    Vm,
}

/// A capability a caller can preflight and an [`crate::Error::Unsupported`]
/// can name. Serialized as a dotted path, e.g. `"exec.stdio_process"`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum Capability {
    #[serde(rename = "lifecycle.pause")]
    LifecyclePause,
    #[serde(rename = "lifecycle.archive")]
    LifecycleArchive,
    #[serde(rename = "lifecycle.fork")]
    LifecycleFork,
    #[serde(rename = "lifecycle.resize")]
    LifecycleResize,
    #[serde(rename = "lifecycle.recover")]
    LifecycleRecover,
    #[serde(rename = "lifecycle.undelete")]
    LifecycleUndelete,
    #[serde(rename = "lifecycle.refresh_activity")]
    LifecycleRefreshActivity,
    #[serde(rename = "lifecycle.timers")]
    LifecycleTimers,
    #[serde(rename = "lifecycle.labels")]
    LifecycleLabels,
    #[serde(rename = "lifecycle.update_network")]
    LifecycleUpdateNetwork,
    #[serde(rename = "lifecycle.snapshot_sandbox")]
    LifecycleSnapshotSandbox,
    #[serde(rename = "exec.stdin")]
    ExecStdin,
    #[serde(rename = "exec.cancel")]
    ExecCancel,
    #[serde(rename = "exec.stdio_process")]
    ExecStdioProcess,
    #[serde(rename = "fs.upload")]
    FsUpload,
    #[serde(rename = "fs.download")]
    FsDownload,
    #[serde(rename = "fs.permissions")]
    FsPermissions,
    #[serde(rename = "pty")]
    Pty,
    #[serde(rename = "logs")]
    Logs,
    #[serde(rename = "sessions")]
    Sessions,
    #[serde(rename = "access.preview_urls")]
    PreviewUrls,
    #[serde(rename = "access.preview_urls.signed")]
    SignedPreviewUrls,
    #[serde(rename = "access.ssh")]
    Ssh,
    #[serde(rename = "access.ssh.ttl")]
    SshTtl,
    #[serde(rename = "access.ssh.revoke")]
    SshRevoke,
    #[serde(rename = "access.shell_command")]
    ShellCommandAccess,
    #[serde(rename = "access.web_terminal")]
    WebTerminalAccess,
    #[serde(rename = "access.vnc")]
    VncAccess,
    #[serde(rename = "snapshots")]
    Snapshots,
    #[serde(rename = "snapshots.from_image.container")]
    SnapshotsContainerFromImage,
    #[serde(rename = "snapshots.from_image.virtual_machine")]
    SnapshotsVmFromImage,
    #[serde(rename = "snapshots.from_dockerfile.container")]
    SnapshotsContainerFromDockerfile,
    #[serde(rename = "snapshots.from_dockerfile.virtual_machine")]
    SnapshotsVmFromDockerfile,
    #[serde(rename = "snapshots.filesystem")]
    SnapshotsFilesystem,
    #[serde(rename = "snapshots.live_process_state")]
    SnapshotsLiveProcessState,
    #[serde(rename = "snapshots.activation")]
    SnapshotsActivation,
    #[serde(rename = "services")]
    Services,
    #[serde(rename = "volumes")]
    Volumes,
    /// A capability sent by a newer or legacy protocol peer that this
    /// version does not model.
    #[serde(other)]
    Unknown,
}

impl fmt::Display for Capability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Serde holds the canonical dotted path; reuse it for Display.
        let json = serde_json::to_string(self).map_err(|_| fmt::Error)?;
        f.write_str(json.trim_matches('"'))
    }
}

/// Negotiated capability set.
///
/// Captured once at `create`/`attach` (the JSON-RPC `initialize` handshake
/// for plugin providers) and immutable for the life of a handle. Provider
/// level, this is the union upper bound; per sandbox it is authoritative.
/// Capabilities optimize failure timing — capability-gated methods still
/// return [`crate::Error::Unsupported`] when a stale capability meets
/// reality.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Capabilities {
    pub isolation: Isolation,
    #[serde(default)]
    pub lifecycle: LifecycleCaps,
    #[serde(default)]
    pub exec:      ExecCaps,
    #[serde(default)]
    pub fs:        FsCaps,
    #[serde(default)]
    pub search:    SearchCaps,
    #[serde(default)]
    pub git:       GitCaps,
    #[serde(default)]
    pub services:  ServiceCaps,
    #[serde(default)]
    pub pty:       Option<PtyCaps>,
    #[serde(default)]
    pub logs:      Option<LogsCaps>,
    #[serde(default)]
    pub access:    AccessCaps,
    #[serde(default)]
    pub network:   NetworkCaps,
    #[serde(default)]
    pub snapshots: Option<SnapshotCaps>,
    #[serde(default)]
    pub volumes:   Option<VolumeCaps>,
}

impl Capabilities {
    /// A minimal capability set: core lifecycle, buffered exec, derived
    /// filesystem — everything optional absent. Providers start here and
    /// enable what they support.
    pub fn minimal(isolation: Isolation) -> Self {
        Self {
            isolation,
            lifecycle: LifecycleCaps::default(),
            exec: ExecCaps::default(),
            fs: FsCaps::default(),
            search: SearchCaps::default(),
            git: GitCaps::default(),
            services: ServiceCaps::default(),
            pty: None,
            logs: None,
            access: AccessCaps::default(),
            network: NetworkCaps::default(),
            snapshots: None,
            volumes: None,
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
#[non_exhaustive]
pub struct LifecycleCaps {
    pub pause:            bool,
    pub archive:          bool,
    pub fork:             bool,
    pub resize:           bool,
    /// Provider-assisted recovery from the `Error` state.
    pub recover:          bool,
    /// Restore a recently deleted sandbox within the provider's
    /// recovery window.
    pub undelete:         bool,
    pub refresh_activity: bool,
    pub timers:           bool,
    pub labels:           bool,
    pub update_network:   bool,
    /// Snapshot a live sandbox into the provider's snapshot service.
    pub snapshot_sandbox: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
#[non_exhaustive]
pub struct ExecCaps {
    /// Output arrives while the command runs (vs. buffered emulation).
    pub live_streaming:    bool,
    /// Stdout and stderr are genuinely separate streams.
    pub streams_separated: bool,
    pub stdin:             bool,
    pub cancel:            bool,
    /// Long-lived bidirectional stdio processes ([`crate::Exec::spawn_stdio`]).
    pub stdio_process:     bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
#[non_exhaustive]
pub struct FsCaps {
    /// Provider serves file operations natively (vs. exec-derived).
    pub native:      bool,
    pub upload:      bool,
    pub download:    bool,
    pub permissions: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
#[non_exhaustive]
pub struct SearchCaps {
    /// Provider overrides the exec-derived search implementation natively.
    pub native: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
#[non_exhaustive]
pub struct GitCaps {
    /// Provider overrides the exec-derived git implementation natively.
    pub native: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
#[non_exhaustive]
pub struct ServiceCaps {
    /// Provider overrides the exec-derived services implementation
    /// natively.
    pub native: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
#[non_exhaustive]
pub struct PtyCaps {
    pub resize: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
#[non_exhaustive]
pub struct LogsCaps {
    pub provision:  bool,
    pub entrypoint: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
#[non_exhaustive]
pub struct AccessCaps {
    pub preview_urls:        bool,
    pub signed_preview_urls: bool,
    pub ssh:                 bool,
    /// SSH access honors a caller-supplied TTL.
    pub ssh_ttl:             bool,
    /// SSH access can be revoked by token.
    pub ssh_revoke:          bool,
    pub shell_command:       bool,
    pub web_terminal:        bool,
    pub vnc:                 bool,
    /// Protocol v1 compatibility tombstone. VPN setup is guest software
    /// managed through exec, not a sandbox-driver capability.
    #[serde(rename = "vpn")]
    vpn_legacy:              bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
#[non_exhaustive]
pub struct NetworkCaps {
    pub allow_all:         bool,
    pub block_all:         bool,
    pub cidr_allow_list:   bool,
    pub domain_allow_list: bool,
    pub outbound_proxy:    bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
#[non_exhaustive]
pub struct SnapshotCaps {
    /// Aggregate compatibility flag: at least one sandbox kind can be
    /// built from an image.
    pub from_image: bool,
    /// Aggregate compatibility flag: at least one sandbox kind can be
    /// built from a Dockerfile.
    pub from_dockerfile: bool,
    /// Exact sandbox kinds supported for image builds.
    pub from_image_kinds: SandboxKindSupport,
    /// Exact sandbox kinds supported for Dockerfile builds.
    pub from_dockerfile_kinds: SandboxKindSupport,
    /// A sandbox can be captured as filesystem state.
    pub filesystem_from_sandbox: bool,
    /// A sandbox can be captured with its memory and running processes.
    pub live_process_state_from_sandbox: bool,
    pub build_logs: bool,
    /// Snapshots can be deactivated and reactivated
    /// ([`crate::SnapshotProvider::activate`]).
    pub activation: bool,
}

/// Sandbox kinds supported for one creation path.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
#[non_exhaustive]
pub struct SandboxKindSupport {
    pub container:       bool,
    pub virtual_machine: bool,
}

impl SandboxKindSupport {
    pub fn supports(&self, kind: crate::SandboxKind) -> bool {
        match kind {
            crate::SandboxKind::Container => self.container,
            crate::SandboxKind::VirtualMachine => self.virtual_machine,
            _ => false,
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
#[non_exhaustive]
pub struct VolumeCaps {
    /// Volumes attach at sandbox create time only (the common model).
    pub create_time_attach: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capability_serializes_as_dotted_path() {
        let json = serde_json::to_string(&Capability::ExecStdioProcess).expect("serializes");
        assert_eq!(json, "\"exec.stdio_process\"");
        assert_eq!(Capability::LifecyclePause.to_string(), "lifecycle.pause");
    }

    #[test]
    fn minimal_capabilities_have_everything_optional_absent() {
        let caps = Capabilities::minimal(Isolation::None);
        assert!(caps.pty.is_none());
        assert!(caps.snapshots.is_none());
        assert!(!caps.lifecycle.pause);
    }

    #[test]
    fn sandbox_kind_support_is_exact() {
        let support = SandboxKindSupport {
            container: true,
            ..SandboxKindSupport::default()
        };
        assert!(support.supports(crate::SandboxKind::Container));
        assert!(!support.supports(crate::SandboxKind::VirtualMachine));
        assert!(!support.supports(crate::SandboxKind::Unknown));
    }
}
