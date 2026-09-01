use std::time::Duration;

use tokio::time::{Instant, sleep};

use crate::error::{Error, ProviderError, Result};
use crate::id::ProviderKind;
use crate::sandbox::Sandbox;
use crate::state::{SandboxState, SandboxStatus};

/// Polling configuration for [`wait_for_state`].
#[derive(Clone, Copy, Debug)]
pub struct WaitOptions {
    pub interval: Duration,
    /// `None` waits without a deadline.
    pub deadline: Option<Duration>,
}

impl Default for WaitOptions {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(1),
            // fabro's state-change budget: a Daytona resume from
            // archive or a cold start can take well over a minute.
            deadline: Some(Duration::from_secs(120)),
        }
    }
}

/// Polls [`Sandbox::describe`] until the state settles (per
/// [`SandboxState::is_stable`]). Unlike [`wait_for_state`], `Error` is a
/// valid outcome — the caller decides what to do with the settled state.
#[tracing::instrument(skip_all, fields(sandbox_id = %sandbox.id()), err)]
pub async fn wait_for_stable_state(
    sandbox: &dyn Sandbox,
    options: &WaitOptions,
) -> Result<SandboxStatus> {
    let started = Instant::now();
    let mut attempt = 0_u64;
    loop {
        attempt += 1;
        let status = sandbox.describe().await?;
        tracing::debug!(attempt, state = ?status.state, "sandbox state observed");
        if status.state.is_stable() {
            return Ok(status);
        }
        if let Some(deadline) = options.deadline {
            let elapsed = started.elapsed();
            if elapsed >= deadline {
                return Err(Error::Timeout {
                    operation: "waiting for a stable state".to_owned(),
                    elapsed,
                });
            }
        }
        sleep(options.interval).await;
    }
}

/// Polls [`Sandbox::describe`] until the sandbox reaches `target`.
///
/// The one generic wait loop, replacing per-call hand-written loops:
/// fails with the provider's `error_reason` when the sandbox enters
/// [`SandboxState::Error`] (unless `Error` is the target), and with
/// [`Error::Timeout`] when the deadline passes. `Deleted` counts as
/// `Stopped` for ephemeral sandboxes that vanish on stop.
#[tracing::instrument(
    skip_all,
    fields(sandbox_id = %sandbox.id(), target = ?target),
    err
)]
pub async fn wait_for_state(
    sandbox: &dyn Sandbox,
    target: SandboxState,
    options: &WaitOptions,
) -> Result<SandboxStatus> {
    let started = Instant::now();
    let mut attempt = 0_u64;
    loop {
        attempt += 1;
        let status = sandbox.describe().await?;
        tracing::debug!(attempt, state = ?status.state, "sandbox state observed");
        let reached = status.state == target
            || (target == SandboxState::Stopped && status.state == SandboxState::Deleted);
        if reached {
            return Ok(status);
        }
        if status.state == SandboxState::Error {
            return Err(Error::Provider(ProviderError::new(
                ProviderKind::try_new("unknown").expect("static kind is valid"),
                status
                    .error_reason
                    .unwrap_or_else(|| "sandbox entered the error state".to_owned()),
            )));
        }
        if let Some(deadline) = options.deadline {
            let elapsed = started.elapsed();
            if elapsed >= deadline {
                return Err(Error::Timeout {
                    operation: format!("waiting for state {target:?}"),
                    elapsed,
                });
            }
        }
        sleep(options.interval).await;
    }
}
