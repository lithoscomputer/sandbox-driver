//! Exec termination: timeouts, the caller's term and kill tokens, and
//! the stop-grace ladder.

use std::time::{Duration, Instant};

use sandbox_driver::{ExecControls, ExecSpec, Termination};
use tokio::time;
use tokio_util::sync::CancellationToken;

use crate::Conformance;
use crate::check::{CheckOutcome, PASS, SIGKILL, SIGTERM, cleanup, fail};

pub(super) async fn exec_timeout_terminates(ctx: &Conformance) -> CheckOutcome {
    let sandbox = ctx.ready().await?;
    let outcome = async {
        let started = Instant::now();
        let spec = ExecSpec::new("sleep")
            .arg("300")
            .timeout(Duration::from_secs(2));
        let result = sandbox
            .exec()
            .run_streaming(&spec, ExecControls::buffered())
            .await
            .map_err(|error| format!("exec failed: {error}"))?;
        if result.result.termination != Termination::TimedOut {
            return fail(format!(
                "expected TimedOut, got {:?}",
                result.result.termination
            ));
        }
        if started.elapsed() > Duration::from_secs(60) {
            return fail("timeout enforcement took over a minute");
        }
        // A timeout is the provider's own stop, with no caller present to
        // escalate, so it kills. A provider that observes the ending
        // signal must say so.
        if let Some(signal) = result.result.signal {
            if signal != SIGKILL {
                return fail(format!(
                    "expected signal {SIGKILL} on timeout, got {signal} (code {:?})",
                    result.result.exit_code
                ));
            }
        }
        PASS
    }
    .await;
    cleanup(&sandbox).await;
    outcome
}

pub(super) async fn exec_term_terminates(ctx: &Conformance) -> CheckOutcome {
    // `sleep` honors TERM, so one signal ends it.
    exec_stop_terminates(
        ctx,
        |token| ExecControls {
            term: Some(token),
            ..ExecControls::buffered()
        },
        Termination::Cancelled,
        SIGTERM,
    )
    .await
}

pub(super) async fn exec_kill_terminates(ctx: &Conformance) -> CheckOutcome {
    exec_stop_terminates(
        ctx,
        |token| ExecControls {
            kill: Some(token),
            ..ExecControls::buffered()
        },
        Termination::Killed,
        SIGKILL,
    )
    .await
}

/// A `term` is one signal, not a ladder: a command that ignores TERM
/// keeps running until the caller's `kill`, and the result names the
/// kill. A provider that cannot deliver a signal ends the command on the
/// term and reports `Cancelled`; that is honest too.
pub(super) async fn exec_term_does_not_escalate(ctx: &Conformance) -> CheckOutcome {
    if !ctx.caps().exec.stop {
        return Ok(Some("capability exec.stop not declared".to_owned()));
    }
    let sandbox = ctx.ready().await?;
    let outcome = async {
        let term = CancellationToken::new();
        let kill = CancellationToken::new();
        let (term_after, kill_after) = (term.clone(), kill.clone());
        tokio::spawn(async move {
            time::sleep(Duration::from_millis(500)).await;
            term_after.cancel();
            // Longer than any grace a provider used to apply on its own.
            time::sleep(Duration::from_secs(4)).await;
            kill_after.cancel();
        });
        let controls = ExecControls {
            term: Some(term),
            kill: Some(kill),
            ..ExecControls::buffered()
        };
        let started = Instant::now();
        let streaming = sandbox
            .exec()
            .run_streaming(
                &ExecSpec::bash("trap '' TERM; sleep 300").timeout(Duration::from_secs(60)),
                controls,
            )
            .await
            .map_err(|error| format!("exec failed: {error}"))?;
        match streaming.result.termination {
            Termination::Killed => {
                if started.elapsed() < Duration::from_secs(4) {
                    return fail(format!(
                        "the command was killed {:?} after start, before the caller's kill",
                        started.elapsed()
                    ));
                }
                if let Some(signal) = streaming.result.signal {
                    if signal != SIGKILL {
                        return fail(format!("expected signal {SIGKILL}, got {signal}"));
                    }
                }
            }
            Termination::Cancelled if streaming.result.signal.is_none() => {
                // A provider without signal delivery: the term ended it.
            }
            other => {
                return fail(format!(
                    "expected Killed (or Cancelled without a signal), got {other:?} with signal {:?}",
                    streaming.result.signal
                ));
            }
        }
        PASS
    }
    .await;
    cleanup(&sandbox).await;
    outcome
}

/// With a stop grace, the provider's own timeout runs the ladder: TERM
/// first, then KILL once the grace has passed. A command that traps TERM
/// therefore lives through the grace and ends on the KILL, and the
/// result still says it timed out. A provider that cannot deliver a
/// signal ends the command on the TERM; that is honest too.
pub(super) async fn exec_stop_grace_escalates_a_timeout(ctx: &Conformance) -> CheckOutcome {
    if !ctx.caps().exec.stop {
        return Ok(Some("capability exec.stop not declared".to_owned()));
    }
    let sandbox = ctx.ready().await?;
    let outcome = async {
        let started = Instant::now();
        let spec = ExecSpec::bash("trap '' TERM; sleep 300")
            .timeout(Duration::from_secs(2))
            .stop_grace(Duration::from_secs(3));
        let result = sandbox
            .exec()
            .run_streaming(&spec, ExecControls::buffered())
            .await
            .map_err(|error| format!("exec failed: {error}"))?;
        if result.result.termination != Termination::TimedOut {
            return fail(format!(
                "expected TimedOut, got {:?}",
                result.result.termination
            ));
        }
        match result.result.signal {
            Some(SIGKILL) => {
                if started.elapsed() < Duration::from_secs(5) {
                    return fail(format!(
                        "the command was killed {:?} after start, before the grace passed",
                        started.elapsed()
                    ));
                }
            }
            None => {
                // A provider without signal delivery ended it on the TERM.
            }
            Some(signal) => {
                return fail(format!(
                    "expected signal {SIGKILL} after the grace, got {signal} (code {:?})",
                    result.result.exit_code
                ));
            }
        }
        if started.elapsed() > Duration::from_secs(60) {
            return fail("graceful timeout enforcement took over a minute");
        }
        PASS
    }
    .await;
    cleanup(&sandbox).await;
    outcome
}

/// With a stop grace, a caller's `term` is the first rung of the ladder:
/// the provider KILLs on its own once the grace has passed, with no
/// caller `kill`, and the result names the kill.
pub(super) async fn exec_stop_grace_escalates_a_term(ctx: &Conformance) -> CheckOutcome {
    if !ctx.caps().exec.stop {
        return Ok(Some("capability exec.stop not declared".to_owned()));
    }
    let sandbox = ctx.ready().await?;
    let outcome = async {
        let term = CancellationToken::new();
        let term_after = term.clone();
        tokio::spawn(async move {
            time::sleep(Duration::from_millis(500)).await;
            term_after.cancel();
        });
        let controls = ExecControls {
            term: Some(term),
            ..ExecControls::buffered()
        };
        let started = Instant::now();
        let streaming = sandbox
            .exec()
            .run_streaming(
                &ExecSpec::bash("trap '' TERM; sleep 300")
                    .timeout(Duration::from_secs(60))
                    .stop_grace(Duration::from_secs(2)),
                controls,
            )
            .await
            .map_err(|error| format!("exec failed: {error}"))?;
        match streaming.result.termination {
            Termination::Killed => {
                if started.elapsed() < Duration::from_millis(2500) {
                    return fail(format!(
                        "the command was killed {:?} after start, before the grace passed",
                        started.elapsed()
                    ));
                }
                if let Some(signal) = streaming.result.signal {
                    if signal != SIGKILL {
                        return fail(format!("expected signal {SIGKILL}, got {signal}"));
                    }
                }
            }
            Termination::Cancelled if streaming.result.signal.is_none() => {
                // A provider without signal delivery: the term ended it.
            }
            other => {
                return fail(format!(
                    "expected Killed (or Cancelled without a signal), got {other:?} with signal {:?}",
                    streaming.result.signal
                ));
            }
        }
        PASS
    }
    .await;
    cleanup(&sandbox).await;
    outcome
}

/// Fires the stop token `build` places half a second into a long sleep
/// and expects `accepted`. A provider that observes the ending signal
/// must report `accepted_signal`; one that cannot observe it reports
/// none.
async fn exec_stop_terminates(
    ctx: &Conformance,
    build: fn(CancellationToken) -> ExecControls,
    accepted: Termination,
    accepted_signal: i32,
) -> CheckOutcome {
    if !ctx.caps().exec.stop {
        return Ok(Some("capability exec.stop not declared".to_owned()));
    }
    let sandbox = ctx.ready().await?;
    let outcome = async {
        let token = CancellationToken::new();
        let stop_after = token.clone();
        tokio::spawn(async move {
            time::sleep(Duration::from_millis(500)).await;
            stop_after.cancel();
        });
        let streaming = sandbox
            .exec()
            .run_streaming(&ExecSpec::new("sleep").arg("300"), build(token))
            .await
            .map_err(|error| format!("exec failed: {error}"))?;
        if streaming.result.termination != accepted {
            return fail(format!(
                "expected {accepted:?}, got {:?}",
                streaming.result.termination
            ));
        }
        if let Some(signal) = streaming.result.signal {
            if signal != accepted_signal {
                return fail(format!(
                    "expected signal {accepted_signal}, got {signal} (code {:?})",
                    streaming.result.exit_code
                ));
            }
        }
        PASS
    }
    .await;
    cleanup(&sandbox).await;
    outcome
}
