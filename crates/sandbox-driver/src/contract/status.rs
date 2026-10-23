use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::{NetworkPolicy, Resources, SandboxRef};
use crate::SnapshotId;

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
    /// Cannot be reached and is not known to be gone. Never treat as lost.
    Unavailable,
    /// Established to be gone without a confirmed destroy. Never inferred
    /// from failed contact.
    Lost,
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
    /// Workload image in use, when the provider knows one.
    #[serde(default)]
    pub image:     Option<String>,
    #[serde(default)]
    pub snapshot:  Option<SnapshotId>,
    /// What was actually allocated, after any provider rounding. An absent
    /// field was not reported, not zero.
    #[serde(default)]
    pub resources: Resources,
    #[serde(default)]
    pub network:   Option<NetworkPolicy>,
    /// Only currently observed addresses. Not cached addresses from a prior
    /// boot.
    #[serde(default)]
    pub services:  BTreeMap<String, ServiceAddress>,
    /// The provider's console page for this sandbox, when it has one.
    #[serde(default)]
    pub web_url:   Option<String>,
}
