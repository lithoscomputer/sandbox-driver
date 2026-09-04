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
    #[serde(rename = "exec.stdin_stream")]
    ExecStdinStream,
    #[serde(rename = "exec.environment")]
    ExecEnvironment,
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
    #[serde(rename = "search")]
    Search,
    #[serde(rename = "git")]
    Git,
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

    /// Returns whether this set declares the requested optional capability.
    #[must_use]
    pub fn supports(&self, capability: Capability) -> bool {
        match capability {
            Capability::LifecyclePause => self.lifecycle.pause,
            Capability::LifecycleArchive => self.lifecycle.archive,
            Capability::LifecycleFork => self.lifecycle.fork,
            Capability::LifecycleResize => self.lifecycle.resize,
            Capability::LifecycleRecover => self.lifecycle.recover,
            Capability::LifecycleUndelete => self.lifecycle.undelete,
            Capability::LifecycleRefreshActivity => self.lifecycle.refresh_activity,
            Capability::LifecycleTimers => self.lifecycle.timers,
            Capability::LifecycleLabels => self.lifecycle.labels,
            Capability::LifecycleUpdateNetwork => self.lifecycle.update_network,
            Capability::LifecycleSnapshotSandbox => self.lifecycle.snapshot_sandbox,
            Capability::ExecStdin => self.exec.stdin,
            Capability::ExecCancel => self.exec.cancel,
            Capability::ExecStdioProcess => self.exec.stdio_process,
            Capability::ExecStdinStream => self.exec.stdin_stream,
            Capability::ExecEnvironment => self.exec.environment,
            Capability::FsUpload => self.fs.upload,
            Capability::FsDownload => self.fs.download,
            Capability::FsPermissions => self.fs.permissions,
            Capability::Pty => self.pty.is_some(),
            Capability::Logs => self.logs.is_some(),
            Capability::PreviewUrls => self.access.preview_urls,
            Capability::SignedPreviewUrls => self.access.signed_preview_urls,
            Capability::Ssh => self.access.ssh,
            Capability::SshTtl => self.access.ssh_ttl,
            Capability::SshRevoke => self.access.ssh_revoke,
            Capability::ShellCommandAccess => self.access.shell_command,
            Capability::WebTerminalAccess => self.access.web_terminal,
            Capability::VncAccess => self.access.vnc,
            Capability::Snapshots => self.snapshots.is_some(),
            Capability::SnapshotsContainerFromImage => self
                .snapshots
                .as_ref()
                .is_some_and(|caps| caps.from_image_kinds.container),
            Capability::SnapshotsVmFromImage => self
                .snapshots
                .as_ref()
                .is_some_and(|caps| caps.from_image_kinds.virtual_machine),
            Capability::SnapshotsContainerFromDockerfile => self
                .snapshots
                .as_ref()
                .is_some_and(|caps| caps.from_dockerfile_kinds.container),
            Capability::SnapshotsVmFromDockerfile => self
                .snapshots
                .as_ref()
                .is_some_and(|caps| caps.from_dockerfile_kinds.virtual_machine),
            Capability::SnapshotsFilesystem => self
                .snapshots
                .as_ref()
                .is_some_and(|caps| caps.filesystem_from_sandbox),
            Capability::SnapshotsLiveProcessState => self
                .snapshots
                .as_ref()
                .is_some_and(|caps| caps.live_process_state_from_sandbox),
            Capability::SnapshotsActivation => {
                self.snapshots.as_ref().is_some_and(|caps| caps.activation)
            }
            Capability::Search => self.search.supported,
            Capability::Git => self.git.supported,
            Capability::Services => self.services.supported,
            Capability::Volumes => self.volumes.is_some(),
            Capability::Sessions | Capability::Unknown => false,
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
    /// Streamed standard input on [`crate::ExecControls::stdin`].
    pub stdin_stream:      bool,
    /// [`crate::Sandbox::environment`] reports the effective environment.
    pub environment:       bool,
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
    /// The complete search facet is available.
    ///
    /// The wire default is `true` when an older peer sends the original
    /// `{"native": false}` shape: that shape meant callers should use the
    /// exec-derived implementation. `SearchCaps::default()` remains
    /// unsupported for a newly constructed minimal capability set.
    #[serde(default = "default_true")]
    pub supported: bool,
    /// The provider implements search natively instead of using the shared
    /// exec-derived implementation.
    pub native:    bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
#[non_exhaustive]
pub struct GitCaps {
    /// The complete git facet is available.
    ///
    /// The wire default is `true` when an older peer sends the original
    /// `{"native": false}` shape: that shape meant callers should use the
    /// exec-derived implementation. `GitCaps::default()` remains unsupported
    /// for a newly constructed minimal capability set.
    #[serde(default = "default_true")]
    pub supported: bool,
    /// The provider contributes at least one native operation instead of
    /// using the exec-derived implementation for every operation.
    pub native:    bool,
}

const fn default_true() -> bool {
    true
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
#[non_exhaustive]
pub struct ServiceCaps {
    /// The complete background-services facet is available.
    ///
    /// The wire default is `true` when an older peer sends the original
    /// `{"native": false}` shape: that shape meant callers should use the
    /// exec-derived implementation. `ServiceCaps::default()` remains
    /// unsupported for a newly constructed minimal capability set.
    #[serde(default = "default_true")]
    pub supported: bool,
    /// The provider implements service operations natively instead of using
    /// the shared exec-derived implementation.
    pub native:    bool,
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

    type CapabilityEnabler = fn(&mut Capabilities);

    #[test]
    fn capability_serializes_as_dotted_path() {
        let json = serde_json::to_string(&Capability::ExecStdioProcess).expect("serializes");
        assert_eq!(json, "\"exec.stdio_process\"");
        assert_eq!(
            serde_json::to_string(&Capability::Search).expect("search serializes"),
            "\"search\""
        );
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
    fn supports_maps_every_public_capability() {
        let cases: &[(Capability, CapabilityEnabler)] = &[
            (Capability::LifecyclePause, |caps| {
                caps.lifecycle.pause = true;
            }),
            (Capability::LifecycleArchive, |caps| {
                caps.lifecycle.archive = true;
            }),
            (Capability::LifecycleFork, |caps| caps.lifecycle.fork = true),
            (Capability::LifecycleResize, |caps| {
                caps.lifecycle.resize = true;
            }),
            (Capability::LifecycleRecover, |caps| {
                caps.lifecycle.recover = true;
            }),
            (Capability::LifecycleUndelete, |caps| {
                caps.lifecycle.undelete = true;
            }),
            (Capability::LifecycleRefreshActivity, |caps| {
                caps.lifecycle.refresh_activity = true;
            }),
            (Capability::LifecycleTimers, |caps| {
                caps.lifecycle.timers = true;
            }),
            (Capability::LifecycleLabels, |caps| {
                caps.lifecycle.labels = true;
            }),
            (Capability::LifecycleUpdateNetwork, |caps| {
                caps.lifecycle.update_network = true;
            }),
            (Capability::LifecycleSnapshotSandbox, |caps| {
                caps.lifecycle.snapshot_sandbox = true;
            }),
            (Capability::ExecStdin, |caps| caps.exec.stdin = true),
            (Capability::ExecCancel, |caps| caps.exec.cancel = true),
            (Capability::ExecStdioProcess, |caps| {
                caps.exec.stdio_process = true;
            }),
            (Capability::FsUpload, |caps| caps.fs.upload = true),
            (Capability::FsDownload, |caps| caps.fs.download = true),
            (Capability::FsPermissions, |caps| caps.fs.permissions = true),
            (Capability::Pty, |caps| caps.pty = Some(PtyCaps::default())),
            (Capability::Logs, |caps| {
                caps.logs = Some(LogsCaps::default());
            }),
            (Capability::PreviewUrls, |caps| {
                caps.access.preview_urls = true;
            }),
            (Capability::SignedPreviewUrls, |caps| {
                caps.access.signed_preview_urls = true;
            }),
            (Capability::Ssh, |caps| caps.access.ssh = true),
            (Capability::SshTtl, |caps| caps.access.ssh_ttl = true),
            (Capability::SshRevoke, |caps| caps.access.ssh_revoke = true),
            (Capability::ShellCommandAccess, |caps| {
                caps.access.shell_command = true;
            }),
            (Capability::WebTerminalAccess, |caps| {
                caps.access.web_terminal = true;
            }),
            (Capability::VncAccess, |caps| caps.access.vnc = true),
            (Capability::Snapshots, |caps| {
                caps.snapshots = Some(SnapshotCaps::default());
            }),
            (Capability::SnapshotsContainerFromImage, |caps| {
                caps.snapshots = Some(SnapshotCaps {
                    from_image_kinds: SandboxKindSupport {
                        container: true,
                        ..SandboxKindSupport::default()
                    },
                    ..SnapshotCaps::default()
                });
            }),
            (Capability::SnapshotsVmFromImage, |caps| {
                caps.snapshots = Some(SnapshotCaps {
                    from_image_kinds: SandboxKindSupport {
                        virtual_machine: true,
                        ..SandboxKindSupport::default()
                    },
                    ..SnapshotCaps::default()
                });
            }),
            (Capability::SnapshotsContainerFromDockerfile, |caps| {
                caps.snapshots = Some(SnapshotCaps {
                    from_dockerfile_kinds: SandboxKindSupport {
                        container: true,
                        ..SandboxKindSupport::default()
                    },
                    ..SnapshotCaps::default()
                });
            }),
            (Capability::SnapshotsVmFromDockerfile, |caps| {
                caps.snapshots = Some(SnapshotCaps {
                    from_dockerfile_kinds: SandboxKindSupport {
                        virtual_machine: true,
                        ..SandboxKindSupport::default()
                    },
                    ..SnapshotCaps::default()
                });
            }),
            (Capability::SnapshotsFilesystem, |caps| {
                caps.snapshots = Some(SnapshotCaps {
                    filesystem_from_sandbox: true,
                    ..SnapshotCaps::default()
                });
            }),
            (Capability::SnapshotsLiveProcessState, |caps| {
                caps.snapshots = Some(SnapshotCaps {
                    live_process_state_from_sandbox: true,
                    ..SnapshotCaps::default()
                });
            }),
            (Capability::SnapshotsActivation, |caps| {
                caps.snapshots = Some(SnapshotCaps {
                    activation: true,
                    ..SnapshotCaps::default()
                });
            }),
            (Capability::Search, |caps| caps.search.supported = true),
            (Capability::Git, |caps| caps.git.supported = true),
            (Capability::Services, |caps| {
                caps.services.supported = true;
            }),
            (Capability::Volumes, |caps| {
                caps.volumes = Some(VolumeCaps::default());
            }),
        ];
        for &(capability, enable) in cases {
            let mut caps = Capabilities::minimal(Isolation::Vm);
            assert!(!caps.supports(capability), "{capability} starts absent");
            enable(&mut caps);
            assert!(
                caps.supports(capability),
                "{capability} should be supported"
            );
        }
        let caps = Capabilities::minimal(Isolation::Vm);
        assert!(!caps.supports(Capability::Sessions));
        assert!(!caps.supports(Capability::Unknown));
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
