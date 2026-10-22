use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::SandboxRef;

/// Observed lifecycle only. Unavailable and unknown never mean deleted.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SandboxState {
    Creating,
    Starting,
    Running,
    Stopping,
    Stopped,
    Paused,
    Archived,
    Deleting,
    Deleted,
    Unhealthy,
    Unavailable,
    #[serde(other)]
    Unknown,
}

/// Address as seen *from the workload and its one-shot containers*.
/// Port keys are requested service ports; values are current reachable ports.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ServiceAddress {
    pub host:  String,
    pub ports: BTreeMap<u16, u16>,
}

/// Common status fields for new implementations, not a claim that existing
/// providers already implement the readiness/fencing contract.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Status {
    pub reference: SandboxRef,
    pub state:     SandboxState,
    #[serde(default)]
    pub name:      Option<String>,
    #[serde(default)]
    pub labels:    BTreeMap<String, String>,
    /// Only currently observed addresses. Not cached addresses from a prior
    /// boot.
    #[serde(default)]
    pub services:  BTreeMap<String, ServiceAddress>,
}
