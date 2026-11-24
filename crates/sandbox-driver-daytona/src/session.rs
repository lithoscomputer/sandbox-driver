//! Session-backed streaming execution through the Daytona toolbox.
//!
//! The one-shot `execute` endpoint buffers combined output and returns
//! only on completion, so streaming, cancellation, and
//! partial-output-on-timeout all ride on command sessions instead: the
//! command runs asynchronously inside a dedicated session, logs follow
//! over a live stream with server-side stdout/stderr separation, a term
//! sends SIGTERM to the command's process group, and deleting the
//! session kills the command. Ported from fabro's session transport.

use std::future::pending;
use std::time::Duration;
use std::{io, mem, process};

use daytona_sdk::{
    ProcessService, Sandbox as SdkSandbox, SessionCommandLogsResult, SessionExecuteResult,
};
use sandbox_driver::legacy::{Error, OutputCaptureBuffer, Result, Termination, stop_signal};
use tokio::runtime::Handle;
use tokio::time;
use tokio_util::sync::CancellationToken;

use crate::sdk::{DaytonaClient, daytona_error};
use crate::shell::shell_quote;
use crate::toolbox;

/// Bound on session cleanup so a stalled REST call can never block a
/// cancellation or timeout path indefinitely.
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(10);

/// Poll interval for session command status.
const STATUS_POLL: Duration = Duration::from_millis(250);

/// Minimum raw output kept for matching overlapping live and final logs.
/// Public output retention can be zero without losing this overlap window.
const MIN_DEDUP_BYTES: usize = 64 * 1024;

/// One command session, deleted (best-effort, bounded) when closed.
///
/// Deleting the session is also the kill mechanism: Daytona terminates
/// the session's processes and closes its log streams.
pub(crate) struct Session {
    logs:    Option<(DaytonaClient, String)>,
    process: Option<ProcessService>,
    id:      String,
}

impl Session {
    pub(crate) async fn create(client: &DaytonaClient, sandbox: &SdkSandbox) -> Result<Self> {
        let endpoint = toolbox::endpoint(client, &sandbox.id).await?;
        let process = toolbox::process_of(sandbox).await?;
        // Random nonce plus host pid: a session id can never collide
        // with one from a crashed or concurrent driver — including two
        // concurrent execs in one process on a coarse-clock platform,
        // which a time-based nonce does not rule out.
        let nonce: u64 = rand::random();
        let id = format!("sandbox-driver-{}-{nonce:016x}", process::id());
        process
            .create_session(&id)
            .await
            .map_err(|error| daytona_error("creating command session", error))?;
        Ok(Self {
            logs: Some((client.clone(), endpoint)),
            process: Some(process),
            id,
        })
    }

    /// Creates a session and starts `command` in it, as one quoted
    /// `/bin/bash -c` that pins `cwd`, blanks `BASH_ENV`, and runs the
    /// command in its own process group for [`Session::terminate`]. A
    /// session whose command fails to start is closed before the error
    /// returns, so the caller never holds a session with nothing running
    /// in it.
    pub(crate) async fn start_command(
        client: &DaytonaClient,
        sandbox: &SdkSandbox,
        cwd: &str,
        command: &str,
    ) -> Result<(Self, SessionExecuteResult)> {
        let mut session = Self::create(client, sandbox).await?;
        let program = wrap_session_script(&build_session_script(cwd, &session.pid_file(), command));
        match session.execute(&program).await {
            Ok(started) => Ok((session, started)),
            Err(error) => {
                session.close().await;
                Err(error)
            }
        }
    }

    pub(crate) fn id(&self) -> &str {
        &self.id
    }

    /// Where the session script records its command's process group.
    fn pid_file(&self) -> String {
        format!("/tmp/.{}.pid", self.id)
    }

    /// Sends SIGTERM to the command's process group, once, through a
    /// second toolbox command; the command keeps running until it exits
    /// or the session is deleted. A command that has not recorded its
    /// group yet gets a moment to; one that has already ended is left
    /// alone. Only a refused request is an error.
    pub(crate) async fn terminate(&self) -> Result<()> {
        let (client, endpoint) = self
            .logs
            .as_ref()
            .filter(|_| self.process.is_some())
            .ok_or_else(|| Error::invalid_spec("session", "command session is closed"))?;
        let script = format!(
            "pid_file={}; tries=0; \
             while [ ! -s \"$pid_file\" ] && [ \"$tries\" -lt 20 ]; do sleep 0.1; tries=$((tries + 1)); done; \
             if [ -s \"$pid_file\" ]; then kill -TERM \"-$(cat \"$pid_file\")\" 2>/dev/null; fi; exit 0",
            shell_quote(&self.pid_file())
        );
        let request = toolbox::request(
            client,
            endpoint,
            &["process", "execute"],
            Some(serde_json::json!({"command": script, "timeout": CLEANUP_TIMEOUT.as_secs()})),
        );
        let status = match time::timeout(CLEANUP_TIMEOUT, request).await {
            Ok(response) => response?.0,
            Err(_) => {
                return Err(Error::io(
                    "terminating session command",
                    io::Error::other("request timed out"),
                ));
            }
        };
        if !(200..300).contains(&status) {
            return Err(Error::io(
                "terminating session command",
                io::Error::other(format!("HTTP {status}")),
            ));
        }
        Ok(())
    }

    fn service(&self) -> Result<&ProcessService> {
        self.process
            .as_ref()
            .ok_or_else(|| Error::invalid_spec("session", "command session is closed"))
    }

    /// Starts the command asynchronously; the result usually carries
    /// only `cmd_id`, but a command that completed synchronously comes
    /// back with its exit code.
    pub(crate) async fn execute(&self, command: &str) -> Result<SessionExecuteResult> {
        self.service()?
            .execute_session_command(&self.id, command, true, true)
            .await
            .map_err(|error| daytona_error("executing session command", error))
    }

    pub(crate) async fn exit_code(&self, command_id: &str) -> Result<Option<i32>> {
        let command = self
            .service()?
            .get_session_command(&self.id, command_id)
            .await
            .map_err(|error| daytona_error("polling session command", error))?;
        Ok(command.exit_code)
    }

    /// Best-effort final log fetch; `None` on any failure or after
    /// `close` — the caller falls back to what the stream delivered.
    pub(crate) async fn fetch_logs(&self, command_id: &str) -> Option<SessionCommandLogsResult> {
        self.process.as_ref()?;
        let (client, endpoint) = self.logs.as_ref()?;
        let outcome = time::timeout(
            CLEANUP_TIMEOUT,
            toolbox::request(
                client,
                endpoint,
                &[
                    "process", "session", &self.id, "command", command_id, "logs",
                ],
                None,
            ),
        )
        .await;
        match outcome {
            Ok(Ok((status, bytes))) if (200..300).contains(&status) => Some(parse_logs(&bytes)),
            _ => {
                tracing::debug!("bounded final command log fetch failed");
                None
            }
        }
    }

    /// Deletes the session within a deadline. Only a successful response
    /// confirms cleanup and termination of any command still running.
    pub(crate) async fn close(&mut self) -> bool {
        let Some(process) = self.process.as_ref() else {
            return true;
        };
        let confirmed = match time::timeout(CLEANUP_TIMEOUT, process.delete_session(&self.id)).await
        {
            Ok(Ok(())) => true,
            Ok(Err(error)) => {
                let error = daytona_error("deleting command session", error);
                tracing::warn!(error = %error, "command session cleanup failed");
                false
            }
            Err(_) => {
                tracing::warn!("command session cleanup timed out");
                false
            }
        };
        self.process.take();
        confirmed
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
                match time::timeout(CLEANUP_TIMEOUT, process.delete_session(&id)).await {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => {
                        let error = daytona_error("deleting dropped command session", error);
                        tracing::warn!(error = %error, "dropped command session cleanup failed");
                    }
                    Err(_) => tracing::warn!("dropped command session cleanup timed out"),
                }
            });
        } else {
            tracing::warn!("command session cleanup skipped without a runtime");
        }
    }
}

/// Bash source run inside the session's `/bin/bash -c`: pin the working
/// directory, blank `BASH_ENV` (sandbox-level hygiene; the command's own
/// env comes with it, see [`crate::shell::exec_line`]), then run the
/// command in a subshell so its exit status is the script's. Job control
/// gives the subshell its own process group, recorded in `pid_file`, so a
/// term signals the command and leaves this script to report its status.
fn build_session_script(cwd: &str, pid_file: &str, command: &str) -> String {
    [
        format!("cd {} || exit $?", shell_quote(cwd)),
        "export BASH_ENV=''".to_owned(),
        format!("pid_file={}", shell_quote(pid_file)),
        "set -m".to_owned(),
        "(".to_owned(),
        command.to_owned(),
        ") &".to_owned(),
        "child=$!".to_owned(),
        "set +m".to_owned(),
        "printf '%s' \"$child\" > \"$pid_file\"".to_owned(),
        "wait \"$child\"".to_owned(),
        "status=$?".to_owned(),
        "rm -f \"$pid_file\"".to_owned(),
        "exit \"$status\"".to_owned(),
    ]
    .join("\n")
}

/// The command handed to the session: one quoted `/bin/bash -c` so the
/// caller's source stays inert until Bash evaluates it, and the session
/// shell resumes afterwards to drain logs and record the exit code.
fn wrap_session_script(script: &str) -> String {
    format!("/bin/bash -c {}", shell_quote(script))
}

/// Toolbox variants: separated JSON, a JSON string, or text with the
/// toolbox's three-byte stdout/stderr markers. The HTTP body is bounded
/// before decoding, so the decoded copies have a finite total size too.
fn parse_logs(bytes: &[u8]) -> SessionCommandLogsResult {
    let parsed = serde_json::from_slice::<serde_json::Value>(bytes).ok();
    if let Some(value) = parsed.as_ref().filter(|value| value.is_object()) {
        return SessionCommandLogsResult {
            stdout:            value
                .get("stdout")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_owned(),
            stderr:            value
                .get("stderr")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_owned(),
            output:            value
                .get("output")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_owned(),
            streams_separated: true,
        };
    }
    let bytes = parsed
        .as_ref()
        .and_then(|value| value.as_str())
        .map_or(bytes, str::as_bytes);
    let mut logs = SessionCommandLogsResult::default();
    let mut remaining = bytes;
    let mut stderr = false;
    loop {
        let marker = remaining
            .windows(3)
            .position(|window| window == [1, 1, 1] || window == [2, 2, 2]);
        let end = marker.unwrap_or(remaining.len());
        let text = String::from_utf8_lossy(&remaining[..end]);
        logs.output.push_str(&text);
        if stderr {
            logs.stderr.push_str(&text);
        } else {
            logs.stdout.push_str(&text);
        }
        let Some(marker) = marker else {
            break;
        };
        stderr = remaining[marker] == 2;
        logs.streams_separated = true;
        remaining = &remaining[marker + 3..];
    }
    logs
}

pub(crate) struct WaitOutcome {
    pub exit_code:   Option<i32>,
    pub termination: Termination,
    /// Fetched eagerly on timeout/stop, before the session is deleted
    /// and the logs go with it.
    pub final_logs:  Option<SessionCommandLogsResult>,
}

/// Polls the command until it exits, the deadline passes, `kill` fires,
/// or the sink-failure token fires (a failing sink cancels the
/// execution). `term` sends SIGTERM to the command once and the poll
/// goes on: a command that then exits reports `Cancelled`, and one that
/// ignores it runs until `kill` or the deadline, which end it by deleting
/// the session. The caller owns the log-stream task and the session
/// close.
pub(crate) async fn wait_for_completion(
    session: &Session,
    command_id: &str,
    initial_exit_code: Option<i32>,
    timeout: Option<Duration>,
    term: Option<&CancellationToken>,
    kill: Option<&CancellationToken>,
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
    tokio::pin!(deadline);
    let mut termed = false;
    loop {
        tokio::select! {
            biased;
            () = stop_signal(kill) => {
                return Ok(WaitOutcome {
                    exit_code:   None,
                    termination: Termination::Killed,
                    final_logs:  session.fetch_logs(command_id).await,
                });
            }
            () = stop_signal(term), if !termed => {
                session.terminate().await?;
                termed = true;
            }
            () = time::sleep(STATUS_POLL) => {
                if let Some(code) = session.exit_code(command_id).await? {
                    // A command that exited after the term was stopped by
                    // it; its logs are fetched before the session goes.
                    return Ok(if termed {
                        WaitOutcome {
                            exit_code:   Some(code),
                            termination: Termination::Cancelled,
                            final_logs:  session.fetch_logs(command_id).await,
                        }
                    } else {
                        WaitOutcome {
                            exit_code:   Some(code),
                            termination: Termination::Exited,
                            final_logs:  None,
                        }
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

/// Keeps enough raw output to compare live and final logs even when the
/// caller retains little or no output. The window always has a finite bound.
pub(crate) fn dedup_capture(retained_output_limit: Option<usize>) -> OutputCaptureBuffer {
    OutputCaptureBuffer::new(Some(
        retained_output_limit.unwrap_or(0).max(MIN_DEDUP_BYTES),
    ))
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
    // The stream ahead of the snapshot: on timeout/stop the final
    // fetch is taken eagerly while the stream keeps draining past it,
    // so the snapshot holds nothing new.
    if seen.starts_with(final_bytes) {
        return final_bytes.len();
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
    fn final_logs_accept_separated_json_and_toolbox_markers() {
        let logs = parse_logs(br#"{"stdout":"out","stderr":"err","output":"outerr"}"#);
        assert!(logs.streams_separated);
        assert_eq!((logs.stdout.as_str(), logs.stderr.as_str()), ("out", "err"));
        let logs = parse_logs(b"\x01\x01\x01out\x02\x02\x02err\x01\x01\x01tail");
        assert!(logs.streams_separated);
        assert_eq!(
            (logs.stdout.as_str(), logs.stderr.as_str()),
            ("outtail", "err")
        );
        let logs = parse_logs(br#""plain\ntext""#);
        assert!(!logs.streams_separated);
        assert_eq!(logs.stdout, "plain\ntext");
    }

    #[test]
    fn plain_suffix_offsets() {
        assert_eq!(plain_suffix_offset(b"abc", b"abcdef"), 3);
        assert_eq!(plain_suffix_offset(b"abc", b"abc"), 3);
        assert_eq!(plain_suffix_offset(b"xabc", b"abcdef"), 3);
        assert_eq!(plain_suffix_offset(b"abc", b"def"), 0);
        assert_eq!(plain_suffix_offset(b"", b"abc"), 0);
        // The stream delivered more than the final snapshot.
        assert_eq!(plain_suffix_offset(b"abcdef", b"abc"), 3);
        assert_eq!(plain_suffix_offset(b"abc", b""), 0);
    }

    #[test]
    fn missing_suffix_is_empty_when_stream_is_ahead_of_snapshot() {
        let mut seen = OutputCaptureBuffer::new(Some(16 * 1024 * 1024));
        seen.push(b"A B C");
        assert!(missing_suffix(&mut seen, b"A B").is_empty());
    }

    #[test]
    fn suffix_offset_uses_observed_length_after_truncation() {
        let mut seen = OutputCaptureBuffer::new(Some(6));
        seen.push(b"abcdefgh");

        assert_eq!(suffix_offset(&mut seen, b"abcdefghij"), 8);
        assert_eq!(suffix_offset(&mut seen, b"abcdefgh"), 8);
        assert_eq!(suffix_offset(&mut seen, b"abcd"), 4);
    }

    #[tokio::test]
    async fn fetch_logs_after_close_is_none() {
        let session = Session {
            logs:    None,
            process: None,
            id:      "closed".to_owned(),
        };
        assert!(session.fetch_logs("cmd").await.is_none());
        assert!(session.exit_code("cmd").await.is_err());
    }

    #[test]
    fn missing_suffix_appends_only_unseen_bytes() {
        let mut seen = OutputCaptureBuffer::new(Some(16 * 1024 * 1024));
        seen.push(b"hello ");
        assert_eq!(missing_suffix(&mut seen, b"hello world"), b"world");
        assert!(missing_suffix(&mut seen, b"hello ").is_empty());
        assert!(missing_suffix(&mut seen, b"").is_empty());
    }

    #[test]
    fn zero_public_retention_preserves_final_log_overlap() {
        let mut raw_seen = dedup_capture(Some(0));
        let mut public_capture = OutputCaptureBuffer::new(Some(0));
        let mut live = vec![b'x'; 128 * 1024];
        live.extend_from_slice(b"abcdef");
        raw_seen.push(&live);
        public_capture.push(&live);

        let missing = missing_suffix(&mut raw_seen, b"cdefgh");
        assert_eq!(missing, b"gh", "the final suffix must still reach the sink");
        public_capture.push(&missing);

        let (retained, stats) = public_capture.into_parts();
        assert!(retained.is_empty());
        assert_eq!(stats.observed_bytes, live.len() + 2);
        assert_eq!(stats.omitted_bytes, stats.observed_bytes);
        assert_eq!(raw_seen.stats().retained_bytes, MIN_DEDUP_BYTES);
    }
}
