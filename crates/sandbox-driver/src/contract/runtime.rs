use std::collections::BTreeMap;
use std::fmt;
use std::num::NonZeroU16;
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio::io::AsyncRead;

use super::{
    Descriptor, Error, ExecControls, ExecOutcome, ExecSpec, LifecycleCapability, PluginTrust,
    ProviderEntry, ProviderName, ProviderSchemas, SandboxRef, SandboxSpec, SandboxState, Source,
    Status,
};
use crate::redact::EnvKeys;
use crate::{FileKind, ProviderKind, SandboxId};

/// Streaming bytes with bounded buffering owned by the provider/adapter.
/// Read errors are transfer failures, never a successful truncated file.
pub type ByteStream = Pin<Box<dyn AsyncRead + Send>>;

/// Explicit application credential store. `None` is absence; failures retain
/// their error classification and must not be mistaken for missing secrets.
#[async_trait]
pub trait SecretResolver: Send + Sync {
    async fn resolve(&self, name: &str) -> Result<Option<String>, Error>;
}

/// Runtime-only secrets, deliberately neither serializable nor printable.
#[derive(Clone, Default)]
pub struct SecretValues(BTreeMap<String, String>);

impl SecretValues {
    pub fn new(values: BTreeMap<String, String>) -> Self {
        Self(values)
    }
    pub fn values(&self) -> &BTreeMap<String, String> {
        &self.0
    }
}

impl fmt::Debug for SecretValues {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretValues(<redacted>)")
    }
}

/// Only these inputs may reach credential-free metadata discovery. Runtime
/// config, arguments, environment and secrets are intentionally absent.
#[derive(Clone, Debug)]
pub struct PluginLocation {
    pub kind:  ProviderKind,
    pub path:  Option<String>,
    pub trust: Option<PluginTrust>,
}

/// Frozen selected-entry inputs. Built-ins must not read ambient settings;
/// plugin launchers must clear their environment and use exactly `environment`
/// plus `secrets`. Conflicts are rejected before activation.
#[derive(Clone)]
pub struct Activation {
    pub name:        ProviderName,
    pub entry:       ProviderEntry,
    pub schemas:     ProviderSchemas,
    pub environment: BTreeMap<String, String>,
    pub secrets:     SecretValues,
}

impl fmt::Debug for Activation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            name,
            entry,
            schemas,
            environment,
            secrets,
        } = self;
        f.debug_struct("Activation")
            .field("name", name)
            .field("entry", entry)
            .field("schemas", schemas)
            .field("environment_keys", &EnvKeys(environment))
            .field("secrets", secrets)
            .finish()
    }
}

/// Adapter boundary shared by built-in registrations and the plugin loader.
/// Discovery verifies trust before executing code and caches by binary digest.
/// It must be bounded, backend-free, and credential-free. Activation
/// initializes exactly once and never replays a mutation after transport loss.
#[async_trait]
pub trait ProviderFactory: Send + Sync {
    async fn discover(&self, location: &PluginLocation) -> Result<ProviderSchemas, Error>;
    async fn activate(&self, activation: Activation) -> Result<Arc<dyn ProviderRuntime>, Error>;
}

/// Fully resolved workload inputs. Secret values are separate from the saved
/// spec. Providers retain the admitted spec for start; they never reread an
/// environment template. Providers still validate backend-specific options.
#[derive(Clone, Debug)]
pub struct WorkloadAdmission {
    pub spec:        SandboxSpec,
    pub credentials: SecretValues,
}

/// A configured provider entry, shared by all its environments in one process.
/// `describe` reports current facts before reference routing. Handles must bind
/// to their original namespace/generation; a restart makes old handles `Stale`.
/// Stop/destroy fence every admitted workload/service/one-shot or return an
/// honest failure. No implementation may infer absence from failed contact.
#[async_trait]
pub trait ProviderRuntime: Send + Sync {
    async fn describe(&self) -> Result<Descriptor, Error>;
    async fn health(&self) -> Result<Health, Error>;
    async fn create(&self, admission: WorkloadAdmission) -> Result<Box<dyn Sandbox>, Error>;
    async fn attach(&self, id: &SandboxId) -> Result<Box<dyn Sandbox>, Error>;
    async fn list(&self, filter: &LabelFilter) -> Result<Vec<SandboxSummary>, Error>;
    async fn destroy(&self, id: &SandboxId) -> Result<(), Error>;
    /// Ends owned runtime tasks with bounded cleanup; does not implicitly
    /// destroy durable sandboxes. Failure is never proof of stopped execution.
    async fn shutdown(&self) -> Result<(), Error>;
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Health {
    pub healthy: bool,
    pub message: Option<String>,
}

/// Conjunction of exact string comparisons, including empty strings.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct LabelFilter(pub BTreeMap<String, String>);

impl LabelFilter {
    pub fn eq(key: impl Into<String>, value: impl Into<String>) -> Self {
        Self(BTreeMap::from([(key.into(), value.into())]))
    }
    pub fn matches(&self, labels: &BTreeMap<String, String>) -> bool {
        self.0
            .iter()
            .all(|(key, value)| labels.get(key) == Some(value))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SandboxSummary {
    pub reference: SandboxRef,
    pub name:      Option<String>,
    pub state:     SandboxState,
    pub labels:    BTreeMap<String, String>,
}

#[async_trait]
pub trait Sandbox: Send + Sync {
    fn reference(&self) -> SandboxRef;
    fn working_directory(&self) -> &Path;
    fn env(&self) -> &BTreeMap<String, String>;
    async fn status(&self) -> Result<Status, Error>;
    /// Uses the frozen admission, rechecks readiness, and refuses while an old
    /// generation is draining. Success means execution can be admitted.
    async fn start(&self) -> Result<(), Error>;
    /// Success confirms termination of every previously admitted execution,
    /// service and one-shot across all handles/instances. Preserves workspace.
    async fn stop(&self) -> Result<(), Error>;
    async fn exec(&self, spec: ExecSpec, controls: ExecControls) -> Result<ExecOutcome, Error>;
    fn files(&self) -> &dyn Files;
    fn ports(&self) -> &dyn Ports;
    fn lifecycle(&self) -> Option<&dyn Lifecycle> {
        None
    }
    fn endpoints(&self) -> Option<&dyn Endpoints> {
        None
    }
    fn containers(&self) -> Option<&dyn Containers> {
        None
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileRange {
    pub offset: u64,
    pub length: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FileEntry {
    pub path: String,
    pub kind: FileKind,
    pub size: u64,
}

#[async_trait]
pub trait Files: Send + Sync {
    async fn get(&self, path: &str, range: Option<FileRange>) -> Result<ByteStream, Error>;
    /// Creates parents. Success confirms the complete stream was written.
    async fn put(&self, path: &str, bytes: ByteStream) -> Result<(), Error>;
    /// Depth zero returns immediate children; paths address the workload.
    async fn list(&self, path: &str, depth: u32) -> Result<Vec<FileEntry>, Error>;
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Expose {
    pub signed: bool,
    pub ttl_ms: Option<u64>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Exposure {
    pub url:           String,
    pub headers:       BTreeMap<String, String>,
    /// Unix epoch milliseconds.
    pub expires_at_ms: Option<u64>,
}

impl fmt::Debug for Exposure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Exposure")
            .field("url", &"<redacted>")
            .field("headers", &"<redacted>")
            .field("expires_at_ms", &self.expires_at_ms)
            .finish()
    }
}

#[async_trait]
pub trait Ports: Send + Sync {
    async fn expose(&self, port: NonZeroU16, options: Expose) -> Result<Exposure, Error>;
    async fn release(&self, port: NonZeroU16) -> Result<(), Error>;
}

#[async_trait]
pub trait Lifecycle: Send + Sync {
    async fn apply(&self, action: LifecycleCapability) -> Result<(), Error>;
}

#[async_trait]
pub trait Endpoints: Send + Sync {
    async fn ssh(&self, ttl_ms: u64) -> Result<crate::SshAccessInfo, Error>;
    async fn ssh_revoke(&self, token: &str) -> Result<(), Error>;
    async fn shell_command(&self) -> Result<String, Error>;
    async fn vnc(&self) -> Result<crate::VncConnection, Error>;
}

/// Only Image and Dockerfile sources are accepted for one-shot containers.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OneShotSpec {
    pub source: Source,
    pub exec:   ExecSpec,
}

impl OneShotSpec {
    pub fn validate(&self) -> Result<(), Error> {
        if !matches!(self.source, Source::Image(_) | Source::Dockerfile(_)) {
            return Err(Error::invalid_spec(
                "source",
                "one-shot requires an image or Dockerfile",
            ));
        }
        self.source.validate()?;
        self.exec.validate()
    }
}

#[async_trait]
pub trait Containers: Send + Sync {
    /// Runs in this workload's workspace/network/service reachability and
    /// participates in its stop fence. Cleanup is confirmed before success.
    async fn run(&self, spec: OneShotSpec, controls: ExecControls) -> Result<ExecOutcome, Error>;
}
