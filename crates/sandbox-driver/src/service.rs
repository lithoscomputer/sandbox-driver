use std::collections::BTreeMap;
use std::fmt;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::derived::DerivedServices;
use crate::error::Result;
use crate::exec::Exec;
use crate::id::ServiceId;

/// Long-lived background processes inside a sandbox — an MCP server, a
/// dev server, anything that must outlive the exec that started it.
///
/// Distinct from [`crate::Exec`]: an exec is awaited to completion; a
/// service is started, observed, and stopped. The library ships an
/// exec-derived implementation ([`DerivedServices`], the
/// `setsid`-and-pidfile pattern); a provider with a native mechanism may
/// implement this directly. [`crate::Sandbox::services`] hides that choice
/// from callers.
///
/// A sandbox that derives this facet must provide `bash`, `mktemp`, `basename`,
/// `cat`, `tail`, `seq`, and `sleep`. `setsid` is optional; when absent, stop
/// falls back to signaling the service leader instead of its process group.
///
/// Service state is per-boot: services do not survive a sandbox stop or
/// restart, and ids from a previous boot resolve to "not running".
#[async_trait]
pub trait Services: Send + Sync {
    /// Starts a background service and returns its identifier.
    ///
    /// The command follows the Bash contract of [`crate::ExecSpec`] and
    /// runs detached from the spawning exec (its own session), with
    /// stdout and stderr captured for [`Services::logs`].
    async fn spawn(&self, spec: &ServiceSpec) -> Result<ServiceId>;

    /// Observed status. An unknown id reports not running rather than
    /// failing, so callers can poll across restarts.
    async fn status(&self, id: &ServiceId) -> Result<ServiceStatus>;

    /// The newest `tail_bytes` of combined stdout and stderr.
    async fn logs(&self, id: &ServiceId, tail_bytes: usize) -> Result<Vec<u8>>;

    /// Stops the service: best-effort TERM to its process group, a short
    /// grace period, then KILL. Idempotent — stopping an unknown or
    /// already-stopped service succeeds.
    async fn stop(&self, id: &ServiceId) -> Result<()>;
}

/// A sandbox's normalized background-services facet.
///
/// This facade hides whether the provider supplies a native implementation or
/// uses the shared exec-derived implementation.
pub struct ServicesFacet<'a> {
    implementation: ServicesImplementation<'a>,
}

enum ServicesImplementation<'a> {
    Provider(&'a dyn Services),
    Derived(DerivedServices<'a>),
}

impl<'a> ServicesFacet<'a> {
    pub(crate) fn provider(services: &'a dyn Services) -> Self {
        Self {
            implementation: ServicesImplementation::Provider(services),
        }
    }

    pub(crate) fn derived(exec: &'a dyn Exec) -> Self {
        Self {
            implementation: ServicesImplementation::Derived(DerivedServices::new(exec)),
        }
    }

    fn implementation(&self) -> &dyn Services {
        match &self.implementation {
            ServicesImplementation::Provider(services) => *services,
            ServicesImplementation::Derived(services) => services,
        }
    }
}

#[async_trait]
impl Services for ServicesFacet<'_> {
    async fn spawn(&self, spec: &ServiceSpec) -> Result<ServiceId> {
        self.implementation().spawn(spec).await
    }

    async fn status(&self, id: &ServiceId) -> Result<ServiceStatus> {
        self.implementation().status(id).await
    }

    async fn logs(&self, id: &ServiceId, tail_bytes: usize) -> Result<Vec<u8>> {
        self.implementation().logs(id, tail_bytes).await
    }

    async fn stop(&self, id: &ServiceId) -> Result<()> {
        self.implementation().stop(id).await
    }
}

/// Spawn request for [`Services::spawn`].
/// `Debug` redacts the command and env values, as on
/// [`crate::ExecSpec`].
#[derive(Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct ServiceSpec {
    /// Bash source, under the [`crate::Exec`] command contract.
    pub command:     String,
    #[serde(default)]
    pub working_dir: Option<String>,
    #[serde(default)]
    pub env:         BTreeMap<String, String>,
}

impl fmt::Debug for ServiceSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServiceSpec")
            .field("command", &"<redacted>")
            .field("working_dir", &self.working_dir)
            .field("env_keys", &self.env.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl ServiceSpec {
    pub fn new(command: impl Into<String>) -> Self {
        Self {
            command:     command.into(),
            working_dir: None,
            env:         BTreeMap::new(),
        }
    }

    #[must_use]
    pub fn working_dir(mut self, dir: impl Into<String>) -> Self {
        self.working_dir = Some(dir.into());
        self
    }

    #[must_use]
    pub fn env_var(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.env.insert(key.into(), value.into());
        self
    }
}

/// Observed status of a background service.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub struct ServiceStatus {
    pub id:        ServiceId,
    pub running:   bool,
    /// Exit code, when the service has ended and the provider observed
    /// one.
    #[serde(default)]
    pub exit_code: Option<i32>,
}

impl ServiceStatus {
    pub fn new(id: ServiceId, running: bool) -> Self {
        Self {
            id,
            running,
            exit_code: None,
        }
    }
}
