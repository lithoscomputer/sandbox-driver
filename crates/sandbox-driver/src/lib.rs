//! Core traits and types for driving sandboxes across providers.
//!
//! [`Sandboxes`] is the catalog a program calls. It is built from provider
//! entries and a [`Registry`] of [`ProviderFactory`] registrations. A factory
//! activates one [`Provider`] per entry, and a provider creates, attaches,
//! lists and destroys [`Sandbox`] handles.
//!
//! Providers must implement the guarantees in `docs/shared-contract.md`.
//! Serialization here defines common data, not a negotiated wire protocol.

mod admission;
mod capture;
mod catalog;
mod config;
mod descriptor;
mod error;
mod execution;
mod failure;
mod file_ops;
mod id;
mod identity;
#[doc(hidden)]
#[expect(
    clippy::absolute_paths,
    reason = "temporary module: its files keep the paths they had at the crate root"
)]
pub mod legacy;
mod provider;
mod redact;
mod sanitize;
mod schema;
mod status;
mod units;
mod wire_time;
mod workload;

pub use capture::{
    Captured, CapturedOutput, DEFAULT_CAPTURE_BYTES, IncompleteOutput, run_bash, run_captured,
    run_captured_with,
};
pub use catalog::{
    CatalogDiagnostic, CatalogOptions, Found, ProviderFailure, ProviderHandle, Registry,
    SandboxBuilder, Sandboxes, StaticEnvironments,
};
pub use config::{Environment, EnvironmentSource, PluginTrust, ProviderEntry};
pub use descriptor::{
    AccessScope, CapabilitySet, ContainerField, Descriptor, Durability, EndpointCapability,
    Isolation, JsonSchema, Locality, Namespace, NamespaceScope, NetworkMode, PortSupport,
    ProviderSchemas, ResourceCapability, SourceKind, TimerCapability,
};
pub use error::{Error, MutationOutcome, RemainingResource};
pub use execution::{
    ExecControls, ExecOutcome, ExecSpec, OutputLoss, OutputSink, OutputStream, StopLevel,
    TerminalSize, Termination, stop_signal,
};
pub use failure::{CommandError, CommandFailure};
pub use file_ops::{FileStat, create_dir_all, path_exists, remove_path, rename_path, stat_path};
pub use id::{
    EnvironmentName, InvalidIdError, NamespaceId, ProviderKind, ProviderName, SandboxId,
    Sha256Digest, SnapshotId,
};
pub use identity::SandboxRef;
pub use provider::{
    Activation, ByteStream, Containers, Endpoints, Expose, Exposure, FileEntry, FileKind,
    FileRange, Files, Health, LabelFilter, OneShotImage, OneShotSpec, PluginLocation, Ports,
    Provider, ProviderFactory, Sandbox, SandboxSummary, SecretResolver, SecretValues,
    SshAccessInfo, VncConnection, WorkloadAdmission,
};
pub use sanitize::{OutputSanitization, OutputSanitizer};
pub use status::{SandboxState, ServiceAddress, Status};
pub use units::{ParseUnitError, parse_duration_ms, parse_size_mib};
pub use workload::{
    ContainerSpec, NetworkPolicy, ReadinessCheck, Resources, SandboxSpec, ServiceSpec, Source,
    Timers, WorkspaceOwnership,
};

#[cfg(doctest)]
#[doc = include_str!("../../../README.md")]
pub struct ReadmeDoctests;
