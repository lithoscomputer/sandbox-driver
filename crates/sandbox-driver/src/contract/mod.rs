//! Shared declarations for the next sandbox API.
//!
//! This module is additive: it does not change the existing crate-root traits,
//! specs, errors, or protocol v2. Providers must explicitly implement the
//! guarantees in `docs/shared-contract.md` before advertising this contract.
//! Serialization here defines common data, not a negotiated wire protocol.

mod config;
mod descriptor;
mod error;
mod identity;
mod status;
mod workload;

pub use config::{Environment, EnvironmentSource, PluginTrust, ProviderEntry};
pub use descriptor::{
    AccessScope, CapabilitySet, ContainerField, Descriptor, Durability, EndpointCapability,
    JsonSchema, LifecycleCapability, Locality, Namespace, NamespaceScope, NetworkMode, PortSupport,
    ProviderSchemas, ResourceCapability, SourceKind,
};
pub use error::{Error, MutationOutcome, RemainingResource};
pub use identity::SandboxRef;
pub use status::{SandboxState, ServiceAddress, Status};
pub use workload::{
    ContainerSpec, NetworkPolicy, ReadinessCheck, Resources, SandboxSpec, ServiceSpec, Source,
    Timers,
};

pub use crate::id::{EnvironmentName, NamespaceId, ProviderName};
