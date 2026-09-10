//! The TERM, grace, KILL ladder a provider runs for a spec that asks for
//! one.
//!
//! Stops are signals (see [`crate::Exec`]): `term` is one SIGTERM, `kill` one
//! SIGKILL, and the provider's own stops kill outright. A caller that
//! wants a graceful stop used to run the ladder itself over the two
//! tokens, which every consumer then reimplemented. [`ExecSpec::stop_grace`]
//! moves the ladder into the provider: a caller's `term`, the spec's
//! timeout, and a failing sink each send TERM first and KILL only after
//! the grace has passed, so traps run and locks release before the
//! process is destroyed.

use std::future::{self, Future};
use std::time::Duration;

use tokio::time;
use tokio_util::sync::CancellationToken;

use crate::error::Result;
use crate::exec::{ExecControls, ExecSpec, ExecStreamingResult, Termination, stop_signal};

/// Why the ladder fired.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Cause {
    /// The spec's timeout elapsed.
    TimedOut,
    /// The caller fired `term`.
    Stopped,
}

/// Runs `run` under the spec's stop grace, if it has one.
///
/// Without [`ExecSpec::stop_grace`] this is `run(spec, controls)`. With
/// one, the provider's raw stop tokens are driven by a ladder: the
/// caller's `term` or the spec's timeout sends TERM, the grace passes,
/// then KILL; the caller's `kill` is immediate at any point. The timeout
/// moves out of the inner spec so the ladder owns it, and a command the
/// ladder ended because of the timeout reports
/// [`Termination::TimedOut`] whichever signal finally stopped it. A
/// provider that cannot deliver a signal ends the command on the TERM,
/// so the grace never runs there.
///
/// Providers call this at the top of `run_streaming`; `run` reaches it
/// through `run_streaming` the way every bundled provider is built.
pub async fn run_with_stop_grace<Fut>(
    spec: &ExecSpec,
    controls: ExecControls,
    run: impl FnOnce(ExecSpec, ExecControls) -> Fut,
) -> Result<ExecStreamingResult>
where
    Fut: Future<Output = Result<ExecStreamingResult>>,
{
    let Some(grace) = spec.stop_grace else {
        return run(spec.clone(), controls).await;
    };

    let mut inner_spec = spec.clone();
    inner_spec.timeout = None;
    inner_spec.stop_grace = None;
    let inner_term = CancellationToken::new();
    let inner_kill = CancellationToken::new();
    let inner_controls = ExecControls {
        term:                  Some(inner_term.clone()),
        kill:                  Some(inner_kill.clone()),
        stdin:                 controls.stdin.clone(),
        sink:                  controls.sink.clone(),
        retained_output_limit: controls.retained_output_limit,
    };

    let ladder = drive(
        spec.timeout,
        grace,
        controls.term.as_ref(),
        controls.kill.as_ref(),
        &inner_term,
        &inner_kill,
    );
    let mut ladder = std::pin::pin!(ladder);
    let mut running = std::pin::pin!(run(inner_spec, inner_controls));
    let mut cause = None;
    let mut result = loop {
        tokio::select! {
            result = &mut running => break result?,
            // The ladder resolves once, when its KILL has been sent; the
            // guard keeps a finished future from being polled again.
            fired = &mut ladder, if cause.is_none() => cause = Some(fired),
        }
    };
    if cause == Some(Cause::TimedOut)
        && matches!(
            result.result.termination,
            Termination::Cancelled | Termination::Killed
        )
    {
        result.result.termination = Termination::TimedOut;
    }
    Ok(result)
}

/// Waits for the timeout or the caller's stop, fires TERM, waits the
/// grace (or the caller's kill), fires KILL, then reports why and never
/// resolves again.
async fn drive(
    timeout: Option<Duration>,
    grace: Duration,
    term: Option<&CancellationToken>,
    kill: Option<&CancellationToken>,
    inner_term: &CancellationToken,
    inner_kill: &CancellationToken,
) -> Cause {
    let cause = tokio::select! {
        () = sleep_or_never(timeout) => Cause::TimedOut,
        () = stop_signal(term) => Cause::Stopped,
        () = stop_signal(kill) => {
            inner_kill.cancel();
            return Cause::Stopped;
        }
    };
    inner_term.cancel();
    tokio::select! {
        () = time::sleep(grace) => {}
        () = stop_signal(kill) => {}
    }
    inner_kill.cancel();
    cause
}

async fn sleep_or_never(timeout: Option<Duration>) {
    match timeout {
        Some(timeout) => time::sleep(timeout).await,
        None => future::pending().await,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use async_trait::async_trait;

    use super::*;
    use crate::exec::{CaptureStats, Exec, ExecResult};

    /// A command that ignores TERM and ends only on KILL, recording what
    /// it saw.
    struct Stubborn {
        terms: AtomicUsize,
    }

    #[async_trait]
    impl Exec for Stubborn {
        async fn run(&self, _spec: &ExecSpec) -> Result<ExecResult> {
            unreachable!("tests go through run_streaming")
        }

        async fn run_streaming(
            &self,
            spec: &ExecSpec,
            controls: ExecControls,
        ) -> Result<ExecStreamingResult> {
            assert!(spec.timeout.is_none(), "the ladder owns the deadline");
            assert!(
                spec.stop_grace.is_none(),
                "the inner spec asks for no ladder"
            );
            let term = controls.term.expect("ladder term");
            let kill = controls.kill.expect("ladder kill");
            let mut termed = false;
            loop {
                tokio::select! {
                    () = term.cancelled(), if !termed => {
                        self.terms.fetch_add(1, Ordering::SeqCst);
                        termed = true;
                    }
                    () = kill.cancelled() => break,
                }
            }
            let mut result = ExecResult::new(Termination::Killed, None, Duration::from_millis(1));
            result.signal = Some(9);
            Ok(ExecStreamingResult {
                result,
                streams_separated: true,
                live_streaming: true,
                stdout_capture: CaptureStats::default(),
                stderr_capture: CaptureStats::default(),
            })
        }
    }

    fn stubborn() -> Arc<Stubborn> {
        Arc::new(Stubborn {
            terms: AtomicUsize::new(0),
        })
    }

    #[tokio::test(start_paused = true)]
    async fn a_timeout_terms_then_kills_after_the_grace_and_reports_timed_out() {
        let exec = stubborn();
        let spec = ExecSpec::new("sleep")
            .timeout(Duration::from_secs(2))
            .stop_grace(Duration::from_secs(5));
        let started = time::Instant::now();
        let result = run_with_stop_grace(&spec, ExecControls::default(), |spec, controls| {
            let exec = &exec;
            async move { exec.run_streaming(&spec, controls).await }
        })
        .await
        .expect("run");
        assert_eq!(result.result.termination, Termination::TimedOut);
        assert_eq!(result.result.signal, Some(9));
        assert_eq!(exec.terms.load(Ordering::SeqCst), 1);
        assert_eq!(started.elapsed(), Duration::from_secs(7));
    }

    #[tokio::test(start_paused = true)]
    async fn a_callers_term_escalates_after_the_grace_and_reports_the_kill() {
        let exec = stubborn();
        let spec = ExecSpec::new("sleep")
            .no_timeout()
            .stop_grace(Duration::from_secs(3));
        let term = CancellationToken::new();
        let controls = ExecControls {
            term: Some(term.clone()),
            ..ExecControls::default()
        };
        let stopper = term.clone();
        tokio::spawn(async move {
            time::sleep(Duration::from_secs(1)).await;
            stopper.cancel();
        });
        let started = time::Instant::now();
        let result = run_with_stop_grace(&spec, controls, |spec, controls| {
            let exec = &exec;
            async move { exec.run_streaming(&spec, controls).await }
        })
        .await
        .expect("run");
        assert_eq!(result.result.termination, Termination::Killed);
        assert_eq!(exec.terms.load(Ordering::SeqCst), 1);
        assert_eq!(started.elapsed(), Duration::from_secs(4));
    }

    #[tokio::test(start_paused = true)]
    async fn a_callers_kill_cuts_the_grace_short() {
        let exec = stubborn();
        let spec = ExecSpec::new("sleep")
            .no_timeout()
            .stop_grace(Duration::from_secs(30));
        let term = CancellationToken::new();
        let kill = CancellationToken::new();
        let controls = ExecControls {
            term: Some(term.clone()),
            kill: Some(kill.clone()),
            ..ExecControls::default()
        };
        tokio::spawn(async move {
            time::sleep(Duration::from_secs(1)).await;
            term.cancel();
            time::sleep(Duration::from_secs(1)).await;
            kill.cancel();
        });
        let started = time::Instant::now();
        let result = run_with_stop_grace(&spec, controls, |spec, controls| {
            let exec = &exec;
            async move { exec.run_streaming(&spec, controls).await }
        })
        .await
        .expect("run");
        assert_eq!(result.result.termination, Termination::Killed);
        assert_eq!(started.elapsed(), Duration::from_secs(2));
    }

    #[tokio::test]
    async fn without_a_grace_the_spec_and_controls_pass_through_unchanged() {
        struct PassThrough;
        #[async_trait]
        impl Exec for PassThrough {
            async fn run(&self, _spec: &ExecSpec) -> Result<ExecResult> {
                unreachable!()
            }
            async fn run_streaming(
                &self,
                spec: &ExecSpec,
                controls: ExecControls,
            ) -> Result<ExecStreamingResult> {
                assert_eq!(spec.timeout, Some(Duration::from_secs(9)));
                assert!(controls.term.is_none() && controls.kill.is_none());
                Ok(ExecStreamingResult {
                    result:            ExecResult::new(
                        Termination::Exited,
                        Some(0),
                        Duration::ZERO,
                    ),
                    streams_separated: true,
                    live_streaming:    true,
                    stdout_capture:    CaptureStats::default(),
                    stderr_capture:    CaptureStats::default(),
                })
            }
        }
        let spec = ExecSpec::new("true").timeout(Duration::from_secs(9));
        let result = run_with_stop_grace(
            &spec,
            ExecControls::default(),
            |spec, controls| async move { PassThrough.run_streaming(&spec, controls).await },
        )
        .await
        .expect("run");
        assert!(result.result.success());
    }
}
