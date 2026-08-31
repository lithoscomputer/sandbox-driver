use std::collections::BTreeMap;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::error::Result;
use crate::id::ServiceId;

/// Long-lived background processes inside a sandbox — an MCP server, a
/// dev server, anything that must outlive the exec that started it.
///
/// Distinct from [`crate::Exec`]: an exec is awaited to completion; a
/// service is started, observed, and stopped. The library ships an
/// exec-derived implementation ([`crate::DerivedServices`], the
/// `setsid`-and-pidfile pattern); a provider with a native mechanism may
/// implement this directly and declare `Capabilities::services.native`.
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

/// Spawn request for [`Services::spawn`].
#[derive(Clone, Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub struct ServiceSpec {
    /// Bash source, under the [`crate::Exec`] command contract.
    pub command:     String,
    #[serde(default)]
    pub working_dir: Option<String>,
    #[serde(default)]
    pub env:         BTreeMap<String, String>,
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
