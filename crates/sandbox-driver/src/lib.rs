//! Core traits and types for driving sandboxes across providers.
//!
//! A [`SandboxProvider`] manages three resource types: sandboxes, snapshots,
//! and volumes. A [`Sandbox`] is a stateless handle — an ID plus a provider
//! connection — whose functionality is grouped into facet traits ([`Exec`],
//! [`Filesystem`], [`Search`], [`Git`], [`Services`], [`Pty`], [`Logs`], and
//! the access facets). Optional functionality is capability-gated: absence is
//! visible both in the type system (`Option` accessors) and in the serializable
//! [`Capabilities`] structure used for preflight checks and the JSON-RPC
//! plugin handshake.
//!
//! # Runtime contract
//!
//! This crate is async on **Tokio** (1.x) and never creates a runtime of
//! its own — the caller owns runtime creation. Tokio appears in the
//! public API: [`StdioProcess`] carries `tokio::io::{AsyncRead,
//! AsyncWrite}` streams, and [`ExecControls`] carries
//! `tokio_util::sync::CancellationToken`. Event observation is awaited
//! directly and creates no hidden delivery task. Core does no blocking I/O;
//! provider crates document their own spawning and blocking behavior.
//!
//! # Compatibility
//!
//! The provider traits are open for external implementation. Only the core
//! is required: identity accessors, `describe`, `start`/`stop`/`delete`, and
//! the `exec` and `fs` facets. Every optional lifecycle method has a provided
//! default body returning [`Error::Unsupported`], and every optional facet
//! accessor defaults to `None`, so adding an optional action or facet is a
//! non-breaking change. Adding a required method is a major version.
//!
//! # Security
//!
//! "Sandbox" is a resource name, not a security claim. Isolation is a
//! per-provider property declared in [`Capabilities::isolation`] and never
//! assumed. A provider is inside the trust domain of every sandbox it
//! drives.

mod access;
mod capabilities;
mod capture;
mod derived;
mod error;
mod event;
mod exec;
mod fs;
mod git;
mod id;
mod logs;
mod probe;
mod provider;
mod pty;
mod sandbox;
mod sanitize;
mod search;
mod service;
mod spec;
mod state;
#[cfg(test)]
mod test_exec;
mod wait;

pub use access::{
    PreviewUrl, PreviewUrls, ShellCommand, SshAccess, SshAccessInfo, Vnc, VncConnection,
    WebTerminal,
};
pub use capabilities::{
    AccessCaps, Capabilities, Capability, ExecCaps, FsCaps, GitCaps, Isolation, LifecycleCaps,
    LogsCaps, NetworkCaps, PtyCaps, SandboxKindSupport, SearchCaps, ServiceCaps, SnapshotCaps,
    VolumeCaps,
};
pub use capture::OutputCaptureBuffer;
pub use derived::{DerivedFs, DerivedGit, DerivedSearch, DerivedServices};
pub use error::{
    AuthError, Error, ExecFailure, ProviderError, ResourceKind, Result, TransportError,
};
pub use event::{
    Action, CorrelationId, ErrorReport, Event, EventBody, EventContext, EventEmitter, EventId,
    EventObserver, EventSourceId, EventSubject, OperationId, OperationReporter, Progress,
    ProgressCode, ProgressUnit, ResourceState,
};
pub use exec::{
    CaptureStats, Exec, ExecControls, ExecResult, ExecSpec, ExecStreamingResult, OutputSink,
    OutputStream, SpawnSpec, StderrTail, StdinSource, StdioProcess, StdioProcessHandle,
    Termination,
};
pub use fs::{DirEntry, FileKind, FileMetadata, Filesystem};
pub use git::{
    Git, GitBranches, GitCloneOptions, GitCommitOptions, GitCredentials, GitFacet, GitPushOptions,
    GitStatus,
};
pub use id::{InvalidIdError, ProviderKind, SandboxId, ServiceId, SnapshotId, VolumeId};
pub use logs::{LogSink, LogSource, Logs};
pub use probe::{BASH_PROBE_SCRIPT, activate, run_bash_probe};
pub use provider::{
    HealthStatus, ProviderHealth, SandboxFilter, SandboxProvider, SnapshotFilter, SnapshotProvider,
    SnapshotSource, SnapshotSpec, SnapshotState, SnapshotStatus, VolumeProvider, VolumeSpec,
    VolumeState, VolumeStatus,
};
pub use pty::{Pty, PtyOptions, PtySession, PtySize};
pub use sandbox::{ForkOptions, Sandbox, SandboxSnapshotOptions, SnapshotMode, WorkspaceOwnership};
pub use sanitize::{OutputSanitization, OutputSanitizer};
pub use search::{GrepMatch, GrepOptions, Search, SearchFacet, WalkOptions, WalkedFile};
pub use service::{ServiceSpec, ServiceStatus, Services, ServicesFacet};
pub use spec::{
    LifecycleTimers, NetworkPolicy, PlatformInfo, Resources, SandboxKind, SandboxSource,
    SandboxSpec, VolumeMount,
};
pub use state::{SandboxState, SandboxStatus};
pub use wait::{WaitOptions, wait_for_stable_state, wait_for_state};
