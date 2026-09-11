//! Retry for git operations against a remote, with the decision about what
//! to retry.
//!
//! A consumer that minted a credential moments ago can have it rejected by
//! GitHub before the token has reached every git endpoint; the rejection
//! arrives as `Repository not found.` or an authentication failure, the
//! same shapes a bad credential produces. Only a credential minted recently
//! makes those shapes safe to retry, and retrying must present the same
//! credential: replication of a given token only makes progress, while a
//! fresh mint would restart that clock. A remote that could not be reached
//! is retried whatever the credential. Everything else fails at once.
//!
//! [`retry_git`] runs an operation under a [`GitRetryPolicy`], decides from
//! the failure class and the credential's age, and returns the attempt
//! history so a consumer can record it. It never replays an operation whose
//! outcome is unknown: a command that timed out or was cancelled may still
//! be running.

use std::fmt;
use std::future::Future;
use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};
use tokio::time::{self, Instant};

use crate::error::{Error, GitFailureKind};
use crate::exec::Termination;
use crate::git::GitCredentials;

/// How long after its mint a credential is presumed to still be replicating
/// to the remote's git endpoints. GitHub's lag is seconds, occasionally tens
/// of seconds.
pub const REPLICATION_HORIZON: Duration = Duration::from_secs(60);

/// Why a failed attempt is worth repeating.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum GitRetryReason {
    /// The remote rejected a credential minted within
    /// [`REPLICATION_HORIZON`]; it may not have reached the git endpoint
    /// yet.
    TokenReplication,
    /// The remote could not be reached or failed on its side, or a mature
    /// credential was rejected in a way that looks like a service blip.
    TransientInfra,
}

impl fmt::Display for GitRetryReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::TokenReplication => "token_replication",
            Self::TransientInfra => "transient_infra",
        })
    }
}

/// Exponential backoff between attempts.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct GitBackoff {
    /// Delay before the second attempt.
    pub initial: Duration,
    /// Growth per attempt.
    pub factor:  f64,
    /// Cap on any single delay.
    pub max:     Duration,
}

impl GitBackoff {
    pub fn new(initial: Duration, factor: f64, max: Duration) -> Self {
        Self {
            initial,
            factor,
            max,
        }
    }

    /// The delay after `attempt` (1-based) has failed.
    #[must_use]
    pub fn delay_after(&self, attempt: u32) -> Duration {
        let exponent = i32::try_from(attempt.saturating_sub(1)).unwrap_or(i32::MAX);
        let delay = self.initial.mul_f64(self.factor.powi(exponent));
        delay.min(self.max)
    }
}

/// Attempt and time bounds for one retried git operation.
///
/// The effective deadline is `start + max_elapsed` when present; each attempt
/// runs with the smaller of `per_attempt_timeout` and the time remaining, and
/// no attempt or backoff starts past the deadline.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct GitRetryPolicy {
    /// Total attempts, including the first.
    pub max_attempts:        u32,
    pub backoff:             GitBackoff,
    /// Wall clock for the whole operation.
    pub max_elapsed:         Option<Duration>,
    /// Cap for any single attempt, handed to the operation as its timeout.
    pub per_attempt_timeout: Option<Duration>,
}

impl GitRetryPolicy {
    pub fn new(max_attempts: u32, backoff: GitBackoff) -> Self {
        Self {
            max_attempts,
            backoff,
            max_elapsed: None,
            per_attempt_timeout: None,
        }
    }

    /// One attempt, no waiting.
    #[must_use]
    pub fn once() -> Self {
        Self::new(1, GitBackoff::new(Duration::ZERO, 1.0, Duration::ZERO))
    }

    #[must_use]
    pub fn max_elapsed(mut self, max_elapsed: Duration) -> Self {
        self.max_elapsed = Some(max_elapsed);
        self
    }

    #[must_use]
    pub fn per_attempt_timeout(mut self, timeout: Duration) -> Self {
        self.per_attempt_timeout = Some(timeout);
        self
    }

    fn deadline(&self, start: Instant) -> Option<Instant> {
        self.max_elapsed.map(|max| start + max)
    }

    /// Time cap for an attempt starting now: the per-attempt cap bounded by
    /// the time remaining before the deadline. `Some(ZERO)` means the
    /// deadline has passed.
    fn attempt_timeout(&self, deadline: Option<Instant>) -> Option<Duration> {
        let remaining = deadline.map(|deadline| deadline.saturating_duration_since(Instant::now()));
        match (self.per_attempt_timeout, remaining) {
            (Some(cap), Some(remaining)) => Some(cap.min(remaining)),
            (Some(cap), None) => Some(cap),
            (None, remaining) => remaining,
        }
    }

    /// The backoff after `attempt` failed, or `None` when it would not fit
    /// before the deadline.
    fn retry_delay(&self, attempt: u32, deadline: Option<Instant>) -> Option<Duration> {
        let delay = self.backoff.delay_after(attempt);
        let fits = deadline
            .is_none_or(|deadline| delay < deadline.saturating_duration_since(Instant::now()));
        fits.then_some(delay)
    }
}

/// What the credential an operation presented says about retrying a
/// rejection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CredentialAge {
    /// Minted within [`REPLICATION_HORIZON`]: a rejection is likely
    /// replication lag.
    Fresh,
    /// Minted earlier: a rejection is indistinguishable from a service blip
    /// at this layer.
    Mature,
    /// No mint time: a fixed credential that waiting cannot make valid, or
    /// no credential at all.
    Static,
}

impl CredentialAge {
    fn of(credentials: Option<&GitCredentials>, now: SystemTime) -> Self {
        match credentials.and_then(|credentials| credentials.minted_at) {
            None => Self::Static,
            Some(minted_at) => match now.duration_since(minted_at) {
                Ok(age) if age < REPLICATION_HORIZON => Self::Fresh,
                Ok(_) => Self::Mature,
                // A mint time in the future is a clock skew; treat the
                // credential as fresh rather than deny it a retry.
                Err(_) => Self::Fresh,
            },
        }
    }
}

/// Whether `error` from an operation that presented `credentials` is worth
/// repeating with the same credentials, and why.
///
/// A remote that could not be reached, a rate limit, and an overloaded
/// transport are transient whatever the credential. A rejected credential
/// is replication lag while the credential is fresh, a service blip when
/// it is mature, and permanent when it is static. Every other class, and
/// any operation whose outcome is unknown (a command that timed out or was
/// cancelled may still be running), is not retried.
#[must_use]
pub fn retry_reason(error: &Error, credentials: Option<&GitCredentials>) -> Option<GitRetryReason> {
    match error {
        Error::Git(failure) => {
            if failure
                .output()
                .is_some_and(|output| output.termination() != Termination::Exited)
            {
                return None;
            }
            decide(
                failure.kind(),
                CredentialAge::of(credentials, SystemTime::now()),
            )
        }
        Error::RateLimited { .. } | Error::Overloaded { .. } => {
            Some(GitRetryReason::TransientInfra)
        }
        _ => None,
    }
}

fn decide(kind: GitFailureKind, age: CredentialAge) -> Option<GitRetryReason> {
    match kind {
        GitFailureKind::RemoteUnavailable => Some(GitRetryReason::TransientInfra),
        GitFailureKind::AuthRejected => match age {
            CredentialAge::Fresh => Some(GitRetryReason::TokenReplication),
            CredentialAge::Mature => Some(GitRetryReason::TransientInfra),
            CredentialAge::Static => None,
        },
        _ => None,
    }
}

/// One attempt of a retried operation.
#[derive(Debug)]
#[non_exhaustive]
pub struct GitAttempt {
    /// 1-based attempt number.
    pub attempt:      u32,
    pub started_at:   SystemTime,
    pub duration:     Duration,
    /// The class a failed attempt was retried under, or the class a final
    /// failure was given; `None` for the successful attempt and for a
    /// failure the policy never retries.
    pub retry_reason: Option<GitRetryReason>,
    /// The failure this attempt ended in, for every failed attempt but the
    /// last: the last attempt's failure is [`GitRetryError::error`], and
    /// the successful attempt of a [`GitRetryReport`] has none. Whether an
    /// attempt succeeded is positional: only the last attempt of a report
    /// did.
    pub failure:      Option<Error>,
}

/// A completed retried operation: the value and how many attempts it took.
#[derive(Debug)]
#[non_exhaustive]
pub struct GitRetryReport<T> {
    pub value:    T,
    pub attempts: Vec<GitAttempt>,
}

/// A retried operation that did not complete: every attempt, and the last
/// attempt's failure.
#[derive(Debug, thiserror::Error)]
#[error("{}", .error)]
pub struct GitRetryError {
    pub attempts: Vec<GitAttempt>,
    #[source]
    pub error:    Error,
}

/// Runs `operation` under `policy`, repeating it while [`retry_reason`]
/// says the failure is worth repeating for `credentials`.
///
/// `operation` receives the 1-based attempt number and the timeout the
/// attempt may use, when the policy bounds one; it should hand that timeout
/// to the git call. A retry starts only when its backoff fits before the
/// deadline; a deadline that passes between attempts ends the operation
/// with [`Error::Timeout`].
pub async fn retry_git<T, Op, Fut>(
    policy: &GitRetryPolicy,
    credentials: Option<&GitCredentials>,
    operation_name: &str,
    mut operation: Op,
) -> Result<GitRetryReport<T>, GitRetryError>
where
    Op: FnMut(u32, Option<Duration>) -> Fut,
    Fut: Future<Output = Result<T, Error>>,
{
    let start = Instant::now();
    let deadline = policy.deadline(start);
    let mut attempts = Vec::new();
    let max_attempts = policy.max_attempts.max(1);
    loop {
        let attempt = u32::try_from(attempts.len()).unwrap_or(u32::MAX) + 1;
        let timeout = policy.attempt_timeout(deadline);
        if timeout == Some(Duration::ZERO) {
            return Err(GitRetryError {
                attempts,
                error: Error::Timeout {
                    operation: operation_name.to_owned(),
                    elapsed:   start.elapsed(),
                },
            });
        }
        let started_at = SystemTime::now();
        let began = Instant::now();
        match operation(attempt, timeout).await {
            Ok(value) => {
                attempts.push(GitAttempt {
                    attempt,
                    started_at,
                    duration: began.elapsed(),
                    retry_reason: None,
                    failure: None,
                });
                return Ok(GitRetryReport { value, attempts });
            }
            Err(error) => {
                let reason = retry_reason(&error, credentials);
                let delay = reason.and_then(|_| {
                    (attempt < max_attempts)
                        .then(|| policy.retry_delay(attempt, deadline))
                        .flatten()
                });
                let Some(delay) = delay else {
                    attempts.push(GitAttempt {
                        attempt,
                        started_at,
                        duration: began.elapsed(),
                        retry_reason: reason,
                        failure: None,
                    });
                    return Err(GitRetryError { attempts, error });
                };
                let reason = reason.expect("a delay implies a reason");
                // The failure can carry the remote's output, so log the
                // class rather than the message.
                tracing::warn!(
                    operation = operation_name,
                    attempt,
                    max_attempts,
                    reason = %reason,
                    delay_ms = u64::try_from(delay.as_millis()).unwrap_or(u64::MAX),
                    "git operation failed, retrying with the same credentials"
                );
                attempts.push(GitAttempt {
                    attempt,
                    started_at,
                    duration: began.elapsed(),
                    retry_reason: Some(reason),
                    failure: Some(error),
                });
                time::sleep(delay).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;
    use crate::error::{ExecFailure, GitFailure};

    fn git_failure(stderr: &str) -> Error {
        Error::Git(GitFailure::from_command(
            "git push",
            ExecFailure::new(
                "git push",
                Termination::Exited,
                Some(128),
                Vec::new(),
                stderr.as_bytes().to_vec(),
            ),
        ))
    }

    fn fresh_credentials() -> GitCredentials {
        GitCredentials::new("x-access-token", "ghs_new").minted_at(SystemTime::now())
    }

    fn mature_credentials() -> GitCredentials {
        GitCredentials::new("x-access-token", "ghs_old")
            .minted_at(SystemTime::now() - Duration::from_mins(30))
    }

    #[test]
    fn a_rejected_credential_is_retried_only_while_fresh() {
        let rejected = git_failure("remote: Repository not found.");
        assert_eq!(
            retry_reason(&rejected, Some(&fresh_credentials())),
            Some(GitRetryReason::TokenReplication)
        );
        assert_eq!(
            retry_reason(&rejected, Some(&mature_credentials())),
            Some(GitRetryReason::TransientInfra)
        );
        assert_eq!(
            retry_reason(&rejected, Some(&GitCredentials::new("u", "ghp_static"))),
            None
        );
        assert_eq!(retry_reason(&rejected, None), None);
    }

    #[test]
    fn an_unreachable_remote_is_transient_whatever_the_credential() {
        let unreachable = git_failure("fatal: unable to access: Could not resolve host");
        assert_eq!(
            retry_reason(&unreachable, None),
            Some(GitRetryReason::TransientInfra)
        );
        assert_eq!(
            retry_reason(&Error::RateLimited { retry_after: None }, None),
            Some(GitRetryReason::TransientInfra)
        );
    }

    #[test]
    fn permanent_classes_and_unknown_outcomes_are_not_retried() {
        assert_eq!(
            retry_reason(
                &git_failure("fatal: couldn't find remote ref refs/heads/x"),
                Some(&fresh_credentials())
            ),
            None
        );
        let timed_out = Error::Git(GitFailure::from_command(
            "git push",
            ExecFailure::new(
                "git push",
                Termination::TimedOut,
                None,
                Vec::new(),
                b"Could not resolve host".to_vec(),
            ),
        ));
        assert_eq!(
            retry_reason(&timed_out, Some(&fresh_credentials())),
            None,
            "a command that may still be running is never replayed"
        );
    }

    #[test]
    fn backoff_grows_and_caps() {
        let backoff = GitBackoff::new(Duration::from_secs(3), 3.0, Duration::from_secs(10));
        assert_eq!(backoff.delay_after(1), Duration::from_secs(3));
        assert_eq!(backoff.delay_after(2), Duration::from_secs(9));
        assert_eq!(backoff.delay_after(3), Duration::from_secs(10));
    }

    fn policy() -> GitRetryPolicy {
        GitRetryPolicy::new(
            3,
            GitBackoff::new(Duration::from_secs(3), 3.0, Duration::from_secs(10)),
        )
    }

    #[tokio::test(start_paused = true)]
    async fn a_fresh_credential_retries_a_rejection_and_records_every_attempt() {
        let outcomes = Mutex::new(vec![
            Ok(()),
            Err(git_failure("remote: Repository not found.")),
            Err(git_failure("remote: Repository not found.")),
        ]);
        let credentials = fresh_credentials();
        let report = retry_git(&policy(), Some(&credentials), "git push", |_, _| {
            let outcome = outcomes.lock().unwrap().pop().unwrap();
            async move { outcome }
        })
        .await
        .expect("recovers within the policy");
        assert_eq!(report.attempts.len(), 3);
        assert_eq!(
            report.attempts[0].retry_reason,
            Some(GitRetryReason::TokenReplication)
        );
        assert!(report.attempts[0].failure.is_some());
        assert!(report.attempts[2].failure.is_none());
        assert!(report.attempts[2].retry_reason.is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn a_static_credential_fails_fast_with_the_failure_at_top_level() {
        let credentials = GitCredentials::new("u", "ghp_static");
        let calls = Mutex::new(0);
        let error = retry_git(&policy(), Some(&credentials), "git push", |_, _| {
            *calls.lock().unwrap() += 1;
            async { Err::<(), _>(git_failure("remote: Repository not found.")) }
        })
        .await
        .expect_err("no retry");
        assert_eq!(*calls.lock().unwrap(), 1);
        assert_eq!(error.attempts.len(), 1);
        assert_eq!(error.attempts[0].retry_reason, None);
        assert!(error.attempts[0].failure.is_none());
        assert!(matches!(error.error, Error::Git(_)));
    }

    #[tokio::test(start_paused = true)]
    async fn attempts_stop_at_the_count_and_the_deadline() {
        let credentials = fresh_credentials();
        let calls = Mutex::new(0);
        let error = retry_git(&policy(), Some(&credentials), "git push", |_, _| {
            *calls.lock().unwrap() += 1;
            async { Err::<(), _>(git_failure("remote: Repository not found.")) }
        })
        .await
        .expect_err("exhausted");
        assert_eq!(*calls.lock().unwrap(), 3);
        assert_eq!(error.attempts.len(), 3);
        assert_eq!(
            error.attempts[2].retry_reason,
            Some(GitRetryReason::TokenReplication),
            "the last attempt keeps its class even though no retry followed"
        );

        // A deadline shorter than the first backoff ends after one attempt.
        let bounded = policy().max_elapsed(Duration::from_secs(2));
        let calls = Mutex::new(0);
        let error = retry_git(&bounded, Some(&credentials), "git push", |_, timeout| {
            *calls.lock().unwrap() += 1;
            assert!(timeout.is_some_and(|timeout| timeout <= Duration::from_secs(2)));
            async { Err::<(), _>(git_failure("remote: Repository not found.")) }
        })
        .await
        .expect_err("deadline");
        assert_eq!(*calls.lock().unwrap(), 1);
        assert!(matches!(error.error, Error::Git(_)));

        // An already-expired deadline launches nothing.
        let expired = policy().max_elapsed(Duration::ZERO);
        let calls = Mutex::new(0);
        let error = retry_git(&expired, None, "git push", |_, _| {
            *calls.lock().unwrap() += 1;
            async { Ok::<(), Error>(()) }
        })
        .await
        .expect_err("expired");
        assert_eq!(*calls.lock().unwrap(), 0, "nothing ran past the deadline");
        assert!(error.attempts.is_empty());
        assert!(matches!(error.error, Error::Timeout { .. }));
    }

    #[tokio::test(start_paused = true)]
    async fn the_per_attempt_timeout_is_handed_to_the_operation() {
        let policy = GitRetryPolicy::once().per_attempt_timeout(Duration::from_secs(7));
        let report = retry_git(&policy, None, "git fetch", |attempt, timeout| async move {
            assert_eq!(attempt, 1);
            assert_eq!(timeout, Some(Duration::from_secs(7)));
            Ok::<u32, Error>(42)
        })
        .await
        .expect("succeeds");
        assert_eq!(report.value, 42);
        assert_eq!(report.attempts.len(), 1);
    }
}
