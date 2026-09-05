//! Bounded transport diagnostics. These counters describe local ownership,
//! not proof that remote processes stopped.
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
#[non_exhaustive]
pub struct ServerDiagnostics {
    pub active_io:        usize,
    pub pending_opens:    usize,
    pub execs:            usize,
    pub stdios:           usize,
    pub ptys:             usize,
    pub streams:          usize,
    pub cached_handles:   usize,
    pub background_tasks: usize,
    /// All live tasks in the plugin's Tokio runtime, including this query.
    pub runtime_tasks:    usize,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[non_exhaustive]
pub struct ClientDiagnostics {
    pub active_io:                  usize,
    pub pending_opens:              usize,
    pub handshakes:                 usize,
    pub accept_backoffs:            u64,
    pub authenticated_opens:        u64,
    pub pending_requests:           usize,
    pub cleanup_tasks:              usize,
    pub failed_cleanups:            usize,
    pub event_routes:               usize,
    pub event_contexts:             usize,
    /// All live tasks in the client's Tokio runtime, including application
    /// tasks.
    pub runtime_tasks:              usize,
    pub setup_samples_lost:         u64,
    /// Logical stop deliveries, including those still waiting or interrupted.
    pub stop_requests:              u64,
    pub stop_acknowledgments:       u64,
    /// Longest successful delivery, including reserve-admission retries.
    pub max_stop_acknowledgment_us: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub struct TransportDiagnostics {
    pub client: ClientDiagnostics,
    pub server: ServerDiagnostics,
}
