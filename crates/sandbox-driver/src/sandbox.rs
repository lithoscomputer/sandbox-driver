use std::collections::BTreeMap;
use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::access::{PreviewUrls, ShellCommand, SshAccess, Vnc, WebTerminal};
use crate::capabilities::{Capabilities, Capability};
use crate::error::{Error, Result};
use crate::exec::Exec;
use crate::fs::Filesystem;
use crate::git::Git;
use crate::id::{SandboxId, SnapshotId};
use crate::logs::Logs;
use crate::pty::Pty;
use crate::search::Search;
use crate::service::Services;
use crate::spec::{LifecycleTimers, NetworkPolicy, PlatformInfo, Resources};
use crate::state::SandboxStatus;

/// Who owns a Host sandbox's workspace directory.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum WorkspaceOwnership {
    /// Caller-owned directory designated in the spec. `delete` releases
    /// the handle and never touches its contents.
    Designated,
    /// Library-created temporary workspace. `delete` removes it.
    Managed,
}

/// A sandbox handle: an ID plus a provider connection.
///
/// Stateless by design — the only data a handle carries besides its ID is
/// the capability set negotiated at `create`/`attach`. Current state comes
/// from [`Sandbox::describe`].
///
/// # Compatibility
///
/// Only the core is required: identity, `describe`, `start`/`stop`/
/// `delete`, `working_directory`, `platform_info`, and the `exec` and `fs`
/// facets. Every optional lifecycle method has a provided default body
/// returning [`Error::Unsupported`], and every optional facet accessor
/// defaults to `None` — implementing them is opt-in, and new optional
/// methods are non-breaking.
#[async_trait]
pub trait Sandbox: Send + Sync {
    // -- Identity and introspection (required) --

    fn id(&self) -> &SandboxId;

    /// Capabilities negotiated at `create`/`attach`; immutable for the
    /// life of this handle.
    fn capabilities(&self) -> &Capabilities;

    async fn describe(&self) -> Result<SandboxStatus>;

    /// The workspace directory commands run in by default.
    fn working_directory(&self) -> &str;

    /// Run-scoped scratch directory outside any checkout, when the
    /// provider offers one.
    fn runtime_directory(&self) -> Option<&str> {
        None
    }

    async fn platform_info(&self) -> Result<PlatformInfo>;

    // -- Core lifecycle (required) --

    /// Starts a stopped or archived sandbox. A no-op when already running.
    async fn start(&self) -> Result<()>;

    /// Stops a running sandbox; disk persists.
    async fn stop(&self) -> Result<()>;

    /// Deletes the sandbox. Idempotent: deleting an unknown ID succeeds.
    async fn delete(&self) -> Result<()>;

    // -- Optional lifecycle (provided defaults return Unsupported) --

    /// Freezes the sandbox keeping memory. Distinct from `stop`.
    async fn pause(&self) -> Result<()> {
        Err(Error::unsupported(Capability::LifecyclePause))
    }

    /// Resumes a paused sandbox.
    async fn resume(&self) -> Result<()> {
        Err(Error::unsupported(Capability::LifecyclePause))
    }

    /// Moves a stopped sandbox to cold storage; `start` restores it.
    async fn archive(&self) -> Result<()> {
        Err(Error::unsupported(Capability::LifecycleArchive))
    }

    /// Clones this running sandbox into a new running sandbox.
    ///
    /// Filesystem state, memory, running processes, and process IDs are
    /// preserved.
    async fn fork(&self, options: &ForkOptions) -> Result<Arc<dyn Sandbox>> {
        let _ = options;
        Err(Error::unsupported(Capability::LifecycleFork))
    }

    /// Changes the sandbox's resources.
    async fn resize(&self, resources: &Resources) -> Result<()> {
        let _ = resources;
        Err(Error::unsupported(Capability::LifecycleResize))
    }

    /// Snapshots this sandbox into the provider's snapshot service.
    async fn snapshot(&self, options: &SandboxSnapshotOptions) -> Result<SnapshotId> {
        let _ = options;
        Err(Error::unsupported(Capability::LifecycleSnapshotSandbox))
    }

    /// Provider-assisted recovery from the `Error` state.
    ///
    /// Distinct from [`crate::SandboxProvider::undelete`]: `recover`
    /// repairs a live sandbox that entered `Error`; `undelete` restores
    /// a deleted one.
    async fn recover(&self) -> Result<()> {
        Err(Error::unsupported(Capability::LifecycleRecover))
    }

    /// Keepalive: resets idle timers.
    async fn refresh_activity(&self) -> Result<()> {
        Err(Error::unsupported(Capability::LifecycleRefreshActivity))
    }

    /// Replaces the idle/lifetime timers.
    async fn set_timers(&self, timers: &LifecycleTimers) -> Result<()> {
        let _ = timers;
        Err(Error::unsupported(Capability::LifecycleTimers))
    }

    /// Replaces the label map.
    async fn set_labels(&self, labels: &BTreeMap<String, String>) -> Result<()> {
        let _ = labels;
        Err(Error::unsupported(Capability::LifecycleLabels))
    }

    /// Changes network policy on a live sandbox.
    async fn update_network(&self, policy: &NetworkPolicy) -> Result<()> {
        let _ = policy;
        Err(Error::unsupported(Capability::LifecycleUpdateNetwork))
    }

    // -- Facets --

    /// Command execution (required).
    fn exec(&self) -> &dyn Exec;

    /// File operations (required; may be exec-derived internally).
    fn fs(&self) -> &dyn Filesystem;

    /// Native search, when the provider has one. `None` means use the
    /// library's exec-derived implementation.
    fn search(&self) -> Option<&dyn Search> {
        None
    }

    /// Native git, when the provider has one. `None` means use the
    /// library's exec-derived implementation.
    fn git(&self) -> Option<&dyn Git> {
        None
    }

    /// Native background-service management, when the provider has one.
    /// `None` means use the library's exec-derived implementation
    /// ([`crate::DerivedServices`]).
    fn services(&self) -> Option<&dyn Services> {
        None
    }

    fn pty(&self) -> Option<&dyn Pty> {
        None
    }

    fn logs(&self) -> Option<&dyn Logs> {
        None
    }

    fn preview_urls(&self) -> Option<&dyn PreviewUrls> {
        None
    }

    fn ssh(&self) -> Option<&dyn SshAccess> {
        None
    }

    fn shell_command(&self) -> Option<&dyn ShellCommand> {
        None
    }

    fn web_terminal(&self) -> Option<&dyn WebTerminal> {
        None
    }

    fn vnc(&self) -> Option<&dyn Vnc> {
        None
    }
}

/// Options for [`Sandbox::fork`].
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(default)]
pub struct ForkOptions {
    pub name: Option<String>,
}

/// State captured by a sandbox snapshot.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum SnapshotMode {
    /// Capture persistent filesystem state only.
    #[default]
    Filesystem,
    /// Capture filesystem state, memory, running processes, and process IDs.
    LiveProcessState,
}

/// Options for [`Sandbox::snapshot`].
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(default)]
pub struct SandboxSnapshotOptions {
    pub name: Option<String>,
    pub mode: SnapshotMode,
}
