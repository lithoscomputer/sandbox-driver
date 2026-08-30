//! Session-backed streaming execution through the Daytona toolbox.
//!
//! The one-shot `execute` endpoint buffers combined output and returns
//! only on completion, so streaming, cancellation, and
//! partial-output-on-timeout all ride on command sessions instead: the
//! command runs asynchronously inside a dedicated session, logs follow
//! over a live stream with server-side stdout/stderr separation, and
//! deleting the session kills the command. Ported from fabro's
//! session transport.

use std::future::pending;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::{mem, process};

use daytona_sdk::{
    ProcessService, Sandbox as SdkSandbox, SessionCommandLogsResult, SessionExecuteResult,
};
use sandbox_driver::{OutputCaptureBuffer, Result, Termination};
use tokio::runtime::Handle;
use tokio::time;
use tokio_util::sync::CancellationToken;

use crate::daytona_error;

/// Bound on session cleanup so a stalled REST call can never block a
/// cancellation or timeout path indefinitely.
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(10);

/// Poll interval for session command status.
const STATUS_POLL: Duration = Duration::from_millis(250);

/// One command session, deleted (best-effort, bounded) when closed.
///
/// Deleting the session is also the kill mechanism: Daytona terminates
/// the session's processes and closes its log streams.
pub(crate) struct Session {
    process: Option<ProcessService>,
    id:      String,
}

impl Session {
    pub(crate) async fn create(sandbox: &SdkSandbox) -> Result<Self> {
        let process = sandbox
            .process()
            .await
            .map_err(|error| daytona_error("connecting to the toolbox", &error))?;
        // Nanosecond nonce plus host pid: a session id can never collide
        // with one from a crashed or concurrent driver.
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or_default();
        let id = format!("sandbox-driver-{}-{nonce}", process::id());
        process
            .create_session(&id)
            .await
            .map_err(|error| daytona_error("creating command session", &error))?;
        Ok(Self {
            process: Some(process),
            id,
        })
    }

    pub(crate) fn id(&self) -> &str {
        &self.id
    }

    fn service(&self) -> &ProcessService {
        self.process.as_ref().expect("session is open until close")
    }

    /// Starts the command asynchronously; the result usually carries
    /// only `cmd_id`, but a command that completed synchronously comes
    /// back with its exit code.
    pub(crate) async fn execute(&self, command: &str) -> Result<SessionExecuteResult> {
        self.service()
            .execute_session_command(&self.id, command, true, true)
            .await
            .map_err(|error| daytona_error("executing session command", &error))
    }

    pub(crate) async fn exit_code(&self, command_id: &str) -> Result<Option<i32>> {
        let command = self
            .service()
            .get_session_command(&self.id, command_id)
            .await
            .map_err(|error| daytona_error("polling session command", &error))?;
        Ok(command.exit_code)
    }

    /// Best-effort final log fetch; `None` on any failure — the caller
    /// falls back to what the stream delivered.
    pub(crate) async fn fetch_logs(&self, command_id: &str) -> Option<SessionCommandLogsResult> {
        self.service()
            .get_session_command_logs(&self.id, command_id)
            .await
            .ok()
    }

    /// Deletes the session — killing anything still running in it —
    /// bounded and best-effort: cleanup can never fail a command that
    /// already produced its outcome.
    pub(crate) async fn close(&mut self) {
        let Some(process) = self.process.as_ref() else {
            return;
        };
        let _ = time::timeout(CLEANUP_TIMEOUT, process.delete_session(&self.id)).await;
        self.process.take();
    }
}

impl Drop for Session {
    /// Safety net for a future dropped mid-await: spawn the deletion
    /// when a runtime is available so the session (and its command) is
    /// not left running.
    fn drop(&mut self) {
        let Some(process) = self.process.take() else {
            return;
        };
        let id = mem::take(&mut self.id);
        if let Ok(handle) = Handle::try_current() {
            handle.spawn(async move {
                let _ = time::timeout(CLEANUP_TIMEOUT, process.delete_session(&id)).await;
            });
        }
    }
}

pub(crate) struct WaitOutcome {
    pub exit_code:   Option<i32>,
    pub termination: Termination,
    /// Fetched eagerly on timeout/cancel, before the session is deleted
    /// and the logs go with it.
    pub final_logs:  Option<SessionCommandLogsResult>,
}

/// Polls the command until it exits, the deadline passes, the caller's
/// token fires, or the sink-failure token fires (a failing sink cancels
/// the execution). The caller owns the log-stream task and the session
/// close.
pub(crate) async fn wait_for_completion(
    session: &Session,
    command_id: &str,
    initial_exit_code: Option<i32>,
    timeout: Option<Duration>,
    cancel: Option<CancellationToken>,
    sink_failed: CancellationToken,
) -> Result<WaitOutcome> {
    if let Some(code) = initial_exit_code {
        return Ok(WaitOutcome {
            exit_code:   Some(code),
            termination: Termination::Exited,
            final_logs:  None,
        });
    }
    let deadline = async {
        match timeout {
            Some(timeout) => time::sleep(timeout).await,
            None => pending().await,
        }
    };
    let cancelled = async {
        match &cancel {
            Some(token) => token.cancelled().await,
            None => pending().await,
        }
    };
    tokio::pin!(deadline, cancelled);
    loop {
        tokio::select! {
            () = time::sleep(STATUS_POLL) => {
                if let Some(code) = session.exit_code(command_id).await? {
                    return Ok(WaitOutcome {
                        exit_code:   Some(code),
                        termination: Termination::Exited,
                        final_logs:  None,
                    });
                }
            }
            () = &mut deadline => {
                return Ok(WaitOutcome {
                    exit_code:   None,
                    termination: Termination::TimedOut,
                    final_logs:  session.fetch_logs(command_id).await,
                });
            }
            () = &mut cancelled => {
                return Ok(WaitOutcome {
                    exit_code:   None,
                    termination: Termination::Cancelled,
                    final_logs:  session.fetch_logs(command_id).await,
                });
            }
            () = sink_failed.cancelled() => {
                return Ok(WaitOutcome {
                    exit_code:   None,
                    termination: Termination::Cancelled,
                    final_logs:  session.fetch_logs(command_id).await,
                });
            }
        }
    }
}

/// Bytes of `final_bytes` the buffer has not yet seen. The live stream
/// and the final log fetch overlap arbitrarily (either can be ahead or
/// truncated), so the append point is found from the retained head/tail
/// — fabro's dedup logic, ported with its tests.
pub(crate) fn missing_suffix(seen: &mut OutputCaptureBuffer, final_bytes: &[u8]) -> Vec<u8> {
    let offset = suffix_offset(seen, final_bytes);
    if offset >= final_bytes.len() {
        return Vec::new();
    }
    final_bytes[offset..].to_vec()
}

fn suffix_offset(seen: &mut OutputCaptureBuffer, final_bytes: &[u8]) -> usize {
    let stats = seen.stats();
    if stats.omitted_bytes == 0 {
        return plain_suffix_offset(&seen.to_bytes(), final_bytes);
    }

    let observed_bytes = stats.observed_bytes;
    let (head, tail) = seen.retained_slices();
    if final_bytes.len() >= observed_bytes
        && final_bytes.starts_with(head)
        && tail == &final_bytes[observed_bytes.saturating_sub(tail.len())..observed_bytes]
    {
        return observed_bytes;
    }
    if final_bytes.len() <= observed_bytes && final_bytes.starts_with(head) {
        return final_bytes.len();
    }

    let max_overlap = tail.len().min(final_bytes.len());
    for overlap in (1..=max_overlap).rev() {
        if tail[tail.len() - overlap..] == final_bytes[..overlap] {
            return overlap;
        }
    }
    0
}

fn plain_suffix_offset(seen: &[u8], final_bytes: &[u8]) -> usize {
    if final_bytes.starts_with(seen) {
        return seen.len();
    }
    let max_overlap = seen.len().min(final_bytes.len());
    for overlap in (1..=max_overlap).rev() {
        if seen[seen.len() - overlap..] == final_bytes[..overlap] {
            return overlap;
        }
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_suffix_offsets() {
        assert_eq!(plain_suffix_offset(b"abc", b"abcdef"), 3);
        assert_eq!(plain_suffix_offset(b"abc", b"abc"), 3);
        assert_eq!(plain_suffix_offset(b"xabc", b"abcdef"), 3);
        assert_eq!(plain_suffix_offset(b"abc", b"def"), 0);
        assert_eq!(plain_suffix_offset(b"", b"abc"), 0);
    }

    #[test]
    fn suffix_offset_uses_observed_length_after_truncation() {
        let mut seen = OutputCaptureBuffer::new(Some(6));
        seen.push(b"abcdefgh");

        assert_eq!(suffix_offset(&mut seen, b"abcdefghij"), 8);
        assert_eq!(suffix_offset(&mut seen, b"abcdefgh"), 8);
        assert_eq!(suffix_offset(&mut seen, b"abcd"), 4);
    }

    #[test]
    fn missing_suffix_appends_only_unseen_bytes() {
        let mut seen = OutputCaptureBuffer::new(None);
        seen.push(b"hello ");
        assert_eq!(missing_suffix(&mut seen, b"hello world"), b"world");
        assert!(missing_suffix(&mut seen, b"hello ").is_empty());
        assert!(missing_suffix(&mut seen, b"").is_empty());
    }
}
