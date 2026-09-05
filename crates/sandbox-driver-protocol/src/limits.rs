//! Finite, per-connection transport budgets. Admission never waits for
//! capacity.
use std::sync::Arc;
use std::time::Duration;

use sandbox_driver::{Error, Result};
use serde::{Deserialize, Serialize};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::methods as m;

/// Limits for one client/plugin connection. These defaults are validation
/// targets, not a measured capacity claim. Both peers enforce their own limits.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
#[non_exhaustive]
pub struct TransportLimits {
    pub active_io:                  usize,
    pub pending_opens:              usize,
    pub unauthenticated_handshakes: usize,
    pub provider_requests:          usize,
    pub reserved_requests:          usize,
    pub control_message_bytes:      usize,
    pub queued_control_bytes:       usize,
    pub reserved_control_bytes:     usize,
    pub event_queue_bytes:          usize,
    pub event_queue_messages:       usize,
    pub retained_output_bytes:      usize,
    pub buffered_value_bytes:       usize,
    pub cached_handles:             usize,
    pub output_progress_timeout:    Duration,
    pub hard_cancel_drain_timeout:  Duration,
    pub open_timeout:               Duration,
    pub shutdown_timeout:           Duration,
}

impl Default for TransportLimits {
    fn default() -> Self {
        Self {
            active_io:                  1024,
            pending_opens:              1024,
            unauthenticated_handshakes: 64,
            provider_requests:          2048,
            reserved_requests:          64,
            control_message_bytes:      1024 * 1024,
            queued_control_bytes:       8 * 1024 * 1024,
            reserved_control_bytes:     1024 * 1024,
            event_queue_bytes:          1024 * 1024,
            event_queue_messages:       256,
            retained_output_bytes:      16 * 1024 * 1024,
            buffered_value_bytes:       16 * 1024 * 1024,
            cached_handles:             4096,
            output_progress_timeout:    Duration::from_secs(30),
            hard_cancel_drain_timeout:  Duration::from_secs(5),
            open_timeout:               Duration::from_secs(10),
            shutdown_timeout:           Duration::from_secs(5),
        }
    }
}

impl TransportLimits {
    pub fn validate(&self) -> Result<()> {
        for (name, value) in [
            ("active_io", self.active_io),
            ("pending_opens", self.pending_opens),
            (
                "unauthenticated_handshakes",
                self.unauthenticated_handshakes,
            ),
            ("provider_requests", self.provider_requests),
            ("reserved_requests", self.reserved_requests),
            ("control_message_bytes", self.control_message_bytes),
            ("queued_control_bytes", self.queued_control_bytes),
            ("reserved_control_bytes", self.reserved_control_bytes),
            ("event_queue_bytes", self.event_queue_bytes),
            ("event_queue_messages", self.event_queue_messages),
            ("retained_output_bytes", self.retained_output_bytes),
            ("buffered_value_bytes", self.buffered_value_bytes),
            ("cached_handles", self.cached_handles),
        ] {
            if value == 0 || value > Semaphore::MAX_PERMITS.min(u32::MAX as usize) {
                return Err(Error::invalid_spec(
                    name,
                    "must be positive and fit the transport budget",
                ));
            }
        }
        for (name, duration) in [
            ("output_progress_timeout", self.output_progress_timeout),
            ("hard_cancel_drain_timeout", self.hard_cancel_drain_timeout),
            ("open_timeout", self.open_timeout),
            ("shutdown_timeout", self.shutdown_timeout),
        ] {
            if duration.is_zero() || duration > Duration::from_secs(86400) {
                return Err(Error::invalid_spec(
                    name,
                    "must be positive and at most one day",
                ));
            }
        }
        Ok(())
    }
}

pub(crate) fn acquire(budget: &Arc<Semaphore>, limit: &str) -> Result<OwnedSemaphorePermit> {
    Arc::clone(budget)
        .try_acquire_owned()
        .map_err(|_| Error::Overloaded {
            limit: limit.into(),
        })
}

pub(crate) fn reserved(method: &str) -> bool {
    matches!(
        method,
        m::EXEC_STOP
            | m::EXEC_STDIO_TERMINATE
            | m::PTY_CLOSE
            | m::STREAM_CANCEL
            | m::SHUTDOWN
            | m::SANDBOX_STOP
            | m::SANDBOX_DELETE
            | m::TRANSPORT_DIAGNOSTICS
            | m::PROVIDER_HEALTH
    )
}

pub(crate) fn uses_io(method: &str) -> bool {
    matches!(
        method,
        m::EXEC_STREAM
            | m::ONE_SHOT_RUN
            | m::EXEC_STDIO_OPEN
            | m::PTY_OPEN
            | m::LOGS_FOLLOW
            | m::FS_READ
            | m::FS_WRITE
            | m::SNAPSHOT_BUILD_LOGS
    )
}
