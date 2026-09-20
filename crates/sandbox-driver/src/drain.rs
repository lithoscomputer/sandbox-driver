//! The raw stop race a provider runs under a command's output.
//!
//! Every bundled provider drains a command's output while racing the
//! caller's `term` and `kill` (see [`crate::ExecControls`]), the
//! operation's timeout, and a sink that stops taking output. Each of
//! those asks the command to stop; a kill then gives the output a bounded
//! grace to close before the drain is abandoned. [`run_with_stop_grace`]
//! sits above this race: it turns the spec's grace into raw signals, and
//! this race delivers them.
//!
//! [`run_with_stop_grace`]: crate::run_with_stop_grace

use std::future::{self, Future};
use std::pin::{Pin, pin};
use std::time::Duration;

use tokio::time::{self, Instant};
use tokio_util::sync::CancellationToken;

use crate::error::Result;
use crate::exec::{ExecControls, StopLevel, Termination, stop_signal};
use crate::grace::sleep_or_never;

/// Where the stop ladder stands. A kill always carries its drain
/// deadline, so "kill sent" and "draining" cannot disagree.
#[derive(Clone, Copy, Debug)]
enum StopPhase {
    /// Nothing has been asked of the command.
    Running,
    /// A term went out; a kill may still follow.
    TermSent,
    /// A kill went out; output is drained until `drain_until` at most.
    KillSent { drain_until: Instant },
}

impl StopPhase {
    fn kill_sent(self) -> bool {
        matches!(self, Self::KillSent { .. })
    }

    fn after_kill(drain_grace: Duration) -> Self {
        Self::KillSent {
            drain_until: Instant::now() + drain_grace,
        }
    }

    fn stop_sent(self) -> Option<StopLevel> {
        match self {
            Self::Running => None,
            Self::TermSent => Some(StopLevel::Term),
            Self::KillSent { .. } => Some(StopLevel::Kill),
        }
    }
}

/// How a [`drain_with_stops`] race ended.
#[derive(Debug)]
pub struct DrainOutcome<T> {
    /// Why the command was stopped; [`Termination::Exited`] when nothing
    /// asked it to stop.
    pub termination: Termination,
    /// What the drain produced, or `None` when the grace after a kill ran
    /// out with the drain still pending. The caller still holds that
    /// drain future and decides its fate: drop it, or end its transport
    /// and wait for it some more.
    pub drained:     Option<T>,
    /// The strongest stop sent to the command, if any.
    pub stop_sent:   Option<StopLevel>,
}

/// Drives `drain` — a provider's future that pumps a command's output to
/// completion — while racing the caller's term and kill signals, the
/// `timeout` left on the operation, and a sink that stopped accepting
/// output (`sink_failed`, which the drain cancels when its sink refuses a
/// chunk). Each of those asks the command to stop through `stop`: the
/// caller's `term` sends [`StopLevel::Term`] once and the drain keeps
/// going; the caller's `kill`, the timeout, and a failed sink send
/// [`StopLevel::Kill`], after which the drain has `drain_grace` to
/// finish before it is abandoned and returned as `None`. A sink that
/// fails as the drain ends still gets its kill, so the command does not
/// outlive the caller that stopped listening. A `stop` that fails ends
/// the race with its error.
pub async fn drain_with_stops<T, Fut>(
    mut drain: Pin<&mut impl Future<Output = T>>,
    sink_failed: &CancellationToken,
    controls: &ExecControls,
    timeout: Option<Duration>,
    drain_grace: Duration,
    mut stop: impl FnMut(StopLevel) -> Fut,
) -> Result<DrainOutcome<T>>
where
    Fut: Future<Output = Result<()>>,
{
    let mut termination = Termination::Exited;
    let mut phase = StopPhase::Running;
    let mut termed = pin!(stop_signal(controls.term.as_ref()));
    let mut killed = pin!(stop_signal(controls.kill.as_ref()));
    let mut deadline = pin!(sleep_or_never(timeout));
    let drained = loop {
        let drain_timeout = async {
            match phase {
                StopPhase::KillSent { drain_until } => time::sleep_until(drain_until).await,
                StopPhase::Running | StopPhase::TermSent => future::pending().await,
            }
        };
        tokio::select! {
            drained = &mut drain => break Some(drained),
            () = sink_failed.cancelled(), if !phase.kill_sent() => {
                termination = Termination::Cancelled;
                phase = StopPhase::after_kill(drain_grace);
                stop(StopLevel::Kill).await?;
            }
            () = &mut termed, if matches!(phase, StopPhase::Running) => {
                termination = Termination::Cancelled;
                phase = StopPhase::TermSent;
                stop(StopLevel::Term).await?;
            }
            () = &mut killed, if !phase.kill_sent() => {
                termination = Termination::Killed;
                phase = StopPhase::after_kill(drain_grace);
                stop(StopLevel::Kill).await?;
            }
            () = &mut deadline, if !phase.kill_sent() => {
                termination = Termination::TimedOut;
                phase = StopPhase::after_kill(drain_grace);
                stop(StopLevel::Kill).await?;
            }
            () = drain_timeout => break None,
        }
    };
    // A sink that failed as the drain ended never got its kill: send it,
    // so the command does not outlive the caller that stopped listening.
    let mut stop_sent = phase.stop_sent();
    if sink_failed.is_cancelled() && !phase.kill_sent() {
        termination = Termination::Cancelled;
        stop_sent = Some(StopLevel::Kill);
        stop(StopLevel::Kill).await?;
    }
    Ok(DrainOutcome {
        termination,
        drained,
        stop_sent,
    })
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::sync::Mutex;

    use super::*;
    use crate::error::Error;

    const GRACE: Duration = Duration::from_secs(5);

    /// Records every stop the race sends.
    #[derive(Default)]
    struct Stops(Mutex<Vec<StopLevel>>);

    impl Stops {
        fn record(&self, level: StopLevel) -> future::Ready<Result<()>> {
            self.0.lock().unwrap().push(level);
            future::ready(Ok(()))
        }

        fn sent(&self) -> Vec<StopLevel> {
            self.0.lock().unwrap().clone()
        }
    }

    /// A drain that produces its output after `after`.
    async fn output_after(after: Duration) -> &'static str {
        time::sleep(after).await;
        "output"
    }

    fn cancel_after(token: &CancellationToken, after: Duration) {
        let token = token.clone();
        tokio::spawn(async move {
            time::sleep(after).await;
            token.cancel();
        });
    }

    fn controls(term: &CancellationToken, kill: &CancellationToken) -> ExecControls {
        ExecControls {
            term: Some(term.clone()),
            kill: Some(kill.clone()),
            ..ExecControls::default()
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_drain_that_completes_on_its_own_reports_an_exit() {
        let stops = Stops::default();
        let mut drain = pin!(output_after(Duration::from_secs(1)));
        let outcome = drain_with_stops(
            drain.as_mut(),
            &CancellationToken::new(),
            &ExecControls::default(),
            None,
            GRACE,
            |level| stops.record(level),
        )
        .await
        .expect("race");
        assert_eq!(outcome.termination, Termination::Exited);
        assert_eq!(outcome.drained, Some("output"));
        assert_eq!(outcome.stop_sent, None);
        assert!(stops.sent().is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn a_term_is_sent_once_and_the_drain_keeps_going() {
        let stops = Stops::default();
        let (term, kill) = (CancellationToken::new(), CancellationToken::new());
        cancel_after(&term, Duration::from_secs(1));
        let started = Instant::now();
        let mut drain = pin!(output_after(Duration::from_secs(3)));
        let outcome = drain_with_stops(
            drain.as_mut(),
            &CancellationToken::new(),
            &controls(&term, &kill),
            None,
            GRACE,
            |level| stops.record(level),
        )
        .await
        .expect("race");
        assert_eq!(outcome.termination, Termination::Cancelled);
        assert_eq!(outcome.drained, Some("output"));
        assert_eq!(outcome.stop_sent, Some(StopLevel::Term));
        assert_eq!(stops.sent(), [StopLevel::Term]);
        assert_eq!(started.elapsed(), Duration::from_secs(3));
    }

    #[tokio::test(start_paused = true)]
    async fn a_kill_after_a_term_escalates_and_reports_the_kill() {
        let stops = Stops::default();
        let (term, kill) = (CancellationToken::new(), CancellationToken::new());
        cancel_after(&term, Duration::from_secs(1));
        cancel_after(&kill, Duration::from_secs(2));
        let mut drain = pin!(output_after(Duration::from_secs(3)));
        let outcome = drain_with_stops(
            drain.as_mut(),
            &CancellationToken::new(),
            &controls(&term, &kill),
            None,
            GRACE,
            |level| stops.record(level),
        )
        .await
        .expect("race");
        assert_eq!(outcome.termination, Termination::Killed);
        assert_eq!(outcome.drained, Some("output"));
        assert_eq!(stops.sent(), [StopLevel::Term, StopLevel::Kill]);
    }

    #[tokio::test(start_paused = true)]
    async fn a_kill_abandons_a_drain_that_outlasts_the_grace() {
        let stops = Stops::default();
        let (term, kill) = (CancellationToken::new(), CancellationToken::new());
        cancel_after(&kill, Duration::from_secs(1));
        let started = Instant::now();
        let mut drain = pin!(future::pending::<&'static str>());
        let outcome = drain_with_stops(
            drain.as_mut(),
            &CancellationToken::new(),
            &controls(&term, &kill),
            None,
            GRACE,
            |level| stops.record(level),
        )
        .await
        .expect("race");
        assert_eq!(outcome.termination, Termination::Killed);
        assert_eq!(outcome.drained, None);
        assert_eq!(outcome.stop_sent, Some(StopLevel::Kill));
        assert_eq!(stops.sent(), [StopLevel::Kill]);
        assert_eq!(started.elapsed(), Duration::from_secs(1) + GRACE);
    }

    #[tokio::test(start_paused = true)]
    async fn the_timeout_kills_and_reports_timed_out() {
        let stops = Stops::default();
        let started = Instant::now();
        let mut drain = pin!(output_after(Duration::from_secs(3)));
        let outcome = drain_with_stops(
            drain.as_mut(),
            &CancellationToken::new(),
            &ExecControls::default(),
            Some(Duration::from_secs(2)),
            GRACE,
            |level| stops.record(level),
        )
        .await
        .expect("race");
        assert_eq!(outcome.termination, Termination::TimedOut);
        assert_eq!(outcome.drained, Some("output"));
        assert_eq!(stops.sent(), [StopLevel::Kill]);
        assert_eq!(started.elapsed(), Duration::from_secs(3));
    }

    #[tokio::test(start_paused = true)]
    async fn the_timeout_no_longer_fires_once_a_kill_went_out() {
        let stops = Stops::default();
        let (term, kill) = (CancellationToken::new(), CancellationToken::new());
        cancel_after(&kill, Duration::from_secs(1));
        let mut drain = pin!(output_after(Duration::from_secs(3)));
        let outcome = drain_with_stops(
            drain.as_mut(),
            &CancellationToken::new(),
            &controls(&term, &kill),
            Some(Duration::from_secs(2)),
            GRACE,
            |level| stops.record(level),
        )
        .await
        .expect("race");
        assert_eq!(outcome.termination, Termination::Killed);
        assert_eq!(stops.sent(), [StopLevel::Kill]);
    }

    #[tokio::test(start_paused = true)]
    async fn a_failed_sink_kills_and_reports_cancelled() {
        let stops = Stops::default();
        let sink_failed = CancellationToken::new();
        cancel_after(&sink_failed, Duration::from_secs(1));
        let mut drain = pin!(output_after(Duration::from_secs(2)));
        let outcome = drain_with_stops(
            drain.as_mut(),
            &sink_failed,
            &ExecControls::default(),
            None,
            GRACE,
            |level| stops.record(level),
        )
        .await
        .expect("race");
        assert_eq!(outcome.termination, Termination::Cancelled);
        assert_eq!(outcome.drained, Some("output"));
        assert_eq!(outcome.stop_sent, Some(StopLevel::Kill));
        assert_eq!(stops.sent(), [StopLevel::Kill]);
    }

    #[tokio::test(start_paused = true)]
    async fn a_sink_that_fails_as_the_drain_ends_still_gets_its_kill() {
        let stops = Stops::default();
        let sink_failed = CancellationToken::new();
        // The drain refuses its last chunk and ends in the same poll, so
        // the race sees the completed drain before the failed sink.
        let mut drain = pin!(async {
            sink_failed.cancel();
            "output"
        });
        let outcome = drain_with_stops(
            drain.as_mut(),
            &sink_failed,
            &ExecControls::default(),
            None,
            GRACE,
            |level| stops.record(level),
        )
        .await
        .expect("race");
        assert_eq!(outcome.termination, Termination::Cancelled);
        assert_eq!(outcome.drained, Some("output"));
        assert_eq!(outcome.stop_sent, Some(StopLevel::Kill));
        assert_eq!(stops.sent(), [StopLevel::Kill]);
    }

    #[tokio::test(start_paused = true)]
    async fn a_stop_that_fails_ends_the_race_with_its_error() {
        let (term, kill) = (CancellationToken::new(), CancellationToken::new());
        cancel_after(&kill, Duration::from_secs(1));
        let mut drain = pin!(future::pending::<()>());
        let error = drain_with_stops(
            drain.as_mut(),
            &CancellationToken::new(),
            &controls(&term, &kill),
            None,
            GRACE,
            |_| future::ready(Err(Error::io("stopping", io::Error::other("no route")))),
        )
        .await
        .expect_err("the stop failure surfaces");
        assert!(error.to_string().contains("stopping"), "{error}");
    }
}
