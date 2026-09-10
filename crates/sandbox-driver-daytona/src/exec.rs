use std::result::Result as StdResult;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use std::{io, mem, process};

use async_trait::async_trait;
use daytona_sdk::{DaytonaError, FileSystemService};
use sandbox_driver::{
    Capability, Error, Exec, ExecControls, ExecResult, ExecSpec, ExecStreamingResult,
    OutputCaptureBuffer, OutputSanitizer, OutputSink, OutputStream, Result, SpawnSpec,
    StdioProcess, Termination, run_with_stop_grace,
};
use serde::Deserialize;
use serde_json::json;
use tokio::runtime::Handle;
use tokio::sync::{Mutex, OnceCell};
use tokio::time;
use tokio_util::sync::CancellationToken;

use crate::session::{Session, dedup_capture, missing_suffix, wait_for_completion};
use crate::{DaytonaClient, daytona_error, encoded_exec, exec_line, shell_quote, stdio, toolbox};

#[derive(Deserialize)]
struct BufferedResponse {
    #[serde(rename = "exitCode", default)]
    exit_code: Option<i32>,
    result:    String,
}

/// Bound on waiting for the log stream to close after the command has
/// its outcome; a stream that will not end is abandoned.
const STREAM_DRAIN_GRACE: Duration = Duration::from_secs(10);

/// Extra client-side wait beyond the server-side command timeout.
const TIMEOUT_GRACE: Duration = Duration::from_secs(10);

/// The server-side timeout sent when the spec has none. Omitting the
/// field does not mean "no deadline" — the toolbox applies its own
/// 10-second default and kills the command — so an untimed spec must
/// cross the wire as an explicit, effectively unbounded timeout. One
/// year fits comfortably in the API's `i32` seconds.
const UNBOUNDED_TIMEOUT: Duration = Duration::from_secs(365 * 24 * 60 * 60);

/// The server-side timeout for a spec: its own, rounded up to a whole
/// second, or the unbounded stand-in — never an omitted field. The API
/// field is integer seconds; without the ceiling, a sub-second timeout
/// would truncate to `0` on the wire instead of bounding the command.
fn wire_timeout(spec_timeout: Option<Duration>) -> Duration {
    let Some(timeout) = spec_timeout else {
        return UNBOUNDED_TIMEOUT;
    };
    if timeout.subsec_nanos() > 0 {
        Duration::from_secs(timeout.as_secs() + 1)
    } else {
        timeout
    }
}

/// Bound on deleting a stdin temp file, so cleanup can never stall a
/// command that already completed.
const STDIN_CLEANUP_TIMEOUT: Duration = Duration::from_secs(10);

/// A temporary sandbox file carrying exact stdin bytes.
///
/// The toolbox execute API has no stdin channel, so write-then-EOF is
/// delivered as a file redirection: arbitrary bytes survive verbatim
/// and the command sees EOF, without embedding the data in shell
/// source. fabro's `DaytonaStdinFile`, ported.
struct StdinFile {
    fs:   Option<FileSystemService>,
    path: String,
}

impl StdinFile {
    async fn create(client: &DaytonaClient, sandbox_id: &str, bytes: &[u8]) -> Result<Self> {
        if bytes.len() > sandbox_driver::DEFAULT_BUFFER_BYTES {
            return Err(Error::LimitExceeded {
                limit:     "buffered_value_bytes".into(),
                max_bytes: sandbox_driver::DEFAULT_BUFFER_BYTES,
            });
        }
        let sandbox = client
            .get(sandbox_id)
            .await
            .map_err(|error| daytona_error("fetching sandbox", error))?;
        let fs = sandbox
            .fs()
            .await
            .map_err(|error| daytona_error("connecting to the toolbox", error))?;
        // Random nonce plus host pid: unique even across concurrent
        // execs in one process, so a stale file from a crashed driver
        // can never feed a later command.
        let nonce: u64 = rand::random();
        let path = format!("/tmp/.sandbox-driver-stdin-{}-{nonce:016x}", process::id());
        fs.upload_file_bytes(&path, bytes)
            .await
            .map_err(|error| daytona_error("uploading exec stdin", error))?;
        Ok(Self { fs: Some(fs), path })
    }

    /// Bounded, best-effort deletion. Failures are swallowed: cleanup
    /// must never fail a command that already ran.
    async fn close(&mut self) {
        let Some(fs) = self.fs.as_ref() else {
            return;
        };
        match time::timeout(STDIN_CLEANUP_TIMEOUT, fs.delete_file(&self.path, false)).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                let error = daytona_error("deleting exec stdin file", error);
                tracing::warn!(error = %error, "exec stdin file cleanup failed");
            }
            Err(_) => tracing::warn!("exec stdin file cleanup timed out"),
        }
        self.fs.take();
    }
}

impl Drop for StdinFile {
    /// Safety net for a caller that drops the exec future mid-await:
    /// spawn the deletion when a runtime is available.
    fn drop(&mut self) {
        let Some(fs) = self.fs.take() else {
            return;
        };
        let path = mem::take(&mut self.path);
        if let Ok(handle) = Handle::try_current() {
            handle.spawn(async move {
                match time::timeout(STDIN_CLEANUP_TIMEOUT, fs.delete_file(&path, false)).await {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => {
                        let error = daytona_error("deleting dropped exec stdin file", error);
                        tracing::warn!(error = %error, "dropped exec stdin cleanup failed");
                    }
                    Err(_) => tracing::warn!("dropped exec stdin cleanup timed out"),
                }
            });
        } else {
            tracing::warn!("exec stdin cleanup skipped without a runtime");
        }
    }
}

/// Native command execution with byte-preserving output framing.
pub struct DaytonaExec {
    transport: DaytonaTransport,
}

impl DaytonaExec {
    pub(crate) fn new(client: DaytonaClient, sandbox_id: String, working_dir: String) -> Self {
        Self {
            transport: DaytonaTransport::new(client, sandbox_id, working_dir),
        }
    }
}

#[async_trait]
impl Exec for DaytonaExec {
    async fn run(&self, spec: &ExecSpec) -> Result<ExecResult> {
        self.run_streaming(spec, ExecControls::buffered())
            .await?
            .into_complete()
    }

    async fn run_streaming(
        &self,
        spec: &ExecSpec,
        controls: ExecControls,
    ) -> Result<ExecStreamingResult> {
        encoded_exec::run(&self.transport, spec, controls).await
    }

    async fn spawn_stdio(&self, spec: &SpawnSpec) -> Result<StdioProcess> {
        self.transport.spawn_stdio(spec).await
    }
}

/// Command execution through the Daytona toolbox, on two transports.
///
/// A plain run uses the one-shot `execute` endpoint: combined output
/// after completion (`streams_separated: false`, `live_streaming:
/// false`, stderr empty) at one API call. A run with a sink or stop
/// token uses a command session instead: logs stream live with
/// server-side stdout/stderr separation, stops and timeouts kill the
/// command by deleting its session, and partial output survives a
/// timeout via a final log fetch. The toolbox takes a shell
/// string on both transports, so the spec's environment, program, and
/// arguments are quoted into one `exec env …` word list — the quoting
/// keeps every word literal, and `env` (not `export`) lets variable names
/// that are not shell identifiers through. The environment crosses in the
/// command because the API's `envs` field is not reliably applied.
/// `BASH_ENV` is unset in the composing shell first.
struct DaytonaTransport {
    client:      DaytonaClient,
    sandbox_id:  String,
    working_dir: String,
    endpoint:    OnceCell<String>,
}

impl DaytonaTransport {
    pub(crate) fn new(client: DaytonaClient, sandbox_id: String, working_dir: String) -> Self {
        Self {
            client,
            sandbox_id,
            working_dir,
            endpoint: OnceCell::new(),
        }
    }

    async fn endpoint(&self) -> Result<&String> {
        self.endpoint
            .get_or_try_init(|| toolbox::endpoint(&self.client, &self.sandbox_id))
            .await
    }

    /// Resolves a relative working directory against the sandbox
    /// working directory, matching the fs facet — the toolbox daemon
    /// would otherwise resolve it against its own cwd.
    fn resolve_dir(&self, dir: Option<&str>) -> String {
        match dir {
            None => self.working_dir.clone(),
            Some(dir) if dir.starts_with('/') => dir.to_owned(),
            Some(dir) => format!("{}/{}", self.working_dir.trim_end_matches('/'), dir),
        }
    }

    fn compose(spec: &ExecSpec, stdin_path: Option<&str>) -> String {
        // Sandbox-level hygiene: the composing shell must not carry an
        // image's BASH_ENV into a `bash -c` the caller sends. The spec
        // env applies afterwards, as given.
        let mut program = String::from("unset BASH_ENV\n");
        program.push_str(&exec_line(&spec.env, &spec.program, &spec.args));
        // Write-then-EOF as a file redirection on the program.
        if let Some(path) = stdin_path {
            program.push_str(" < ");
            program.push_str(&shell_quote(path));
        }
        program
    }
}

#[async_trait]
impl Exec for DaytonaTransport {
    async fn run(&self, spec: &ExecSpec) -> Result<ExecResult> {
        let streaming = self.run_streaming(spec, ExecControls::buffered()).await?;
        streaming.into_complete()
    }

    #[tracing::instrument(
        skip_all,
        fields(
            provider_kind = "daytona",
            sandbox_id = %self.sandbox_id,
            has_stdin = spec.stdin.is_some(),
            live_streaming = controls.sink.is_some() || controls.term.is_some() || controls.kill.is_some()
        ),
        err
    )]
    async fn run_streaming(
        &self,
        spec: &ExecSpec,
        controls: ExecControls,
    ) -> Result<ExecStreamingResult> {
        run_with_stop_grace(spec, controls, |spec, controls| async move {
            self.run_signals(&spec, controls).await
        })
        .await
    }

    async fn spawn_stdio(&self, spec: &SpawnSpec) -> Result<StdioProcess> {
        self.spawn_stdio_raw(spec).await
    }
}

impl DaytonaTransport {
    /// Runs the command under raw stop signals; the trait method wraps
    /// this in the spec's stop grace.
    async fn run_signals(
        &self,
        spec: &ExecSpec,
        controls: ExecControls,
    ) -> Result<ExecStreamingResult> {
        if controls.stdin.is_some() {
            return Err(Error::unsupported(Capability::ExecStdinStream));
        }
        // Sessions cost three extra API calls, so plain buffered runs —
        // every derived fs/search/git operation — keep the one-shot
        // endpoint; only a sink or stop token needs the session
        // transport. Daytona ends a command by deleting its session,
        // which is one stop level: a term and a kill end the command the
        // same way, and the result reports whichever was asked for.
        if controls.sink.is_some() || controls.term.is_some() || controls.kill.is_some() {
            return self.run_session(spec, controls).await;
        }
        self.run_buffered(spec, &controls).await
    }

    #[tracing::instrument(
        skip_all,
        fields(provider_kind = "daytona", sandbox_id = %self.sandbox_id),
        err
    )]
    async fn spawn_stdio_raw(&self, spec: &SpawnSpec) -> Result<StdioProcess> {
        stdio::spawn(
            &self.client,
            &self.sandbox_id,
            &self.resolve_dir(spec.working_dir.as_deref()),
            spec,
        )
        .await
    }
}

impl DaytonaTransport {
    async fn run_buffered(
        &self,
        spec: &ExecSpec,
        controls: &ExecControls,
    ) -> Result<ExecStreamingResult> {
        let started = Instant::now();
        let endpoint = self.endpoint().await?;
        let mut stdin_file = match &spec.stdin {
            Some(bytes) => Some(StdinFile::create(&self.client, &self.sandbox_id, bytes).await?),
            None => None,
        };
        let program = Self::compose(spec, stdin_file.as_ref().map(|file| file.path.as_str()));
        let call = async {
            let (status, bytes) = toolbox::request(
                &self.client,
                endpoint,
                &["process", "execute"],
                Some(json!({
                    "command": program,
                    "cwd": self.resolve_dir(spec.working_dir.as_deref()),
                    "timeout": wire_timeout(spec.timeout).as_secs(),
                })),
            )
            .await?;
            if status == 408 {
                return Ok(None);
            }
            if !(200..300).contains(&status) {
                return Err(Error::io(
                    "executing command",
                    io::Error::other(format!("HTTP {status}")),
                ));
            }
            let response: BufferedResponse = serde_json::from_slice(&bytes)
                .map_err(|error| Error::io("decoding command response", io::Error::other(error)))?;
            Ok::<_, Error>(Some(response))
        };
        let response = match spec.timeout {
            Some(timeout) => time::timeout(timeout + TIMEOUT_GRACE, call)
                .await
                .unwrap_or_else(|_| {
                    Err(Error::Incomplete(sandbox_driver::IncompleteOperation::new(
                        "Daytona command timeout",
                    )))
                }),
            None => call.await,
        };
        // Clean up before propagating any failure, so an errored command
        // does not strand its stdin file.
        if let Some(file) = stdin_file.as_mut() {
            file.close().await;
        }
        let response = response?;

        // A response is a completed command, whatever its exit code and
        // however close to the deadline it arrived — classifying a
        // genuine failure as TimedOut would trip retry-on-timeout logic
        // on non-idempotent commands. Timeouts are only ever the 408 or
        // client-deadline paths above.
        let (termination, exit_code, stdout) = match response {
            None => (Termination::TimedOut, None, Vec::new()),
            Some(response) => (
                Termination::Exited,
                Some(response.exit_code.unwrap_or(0)),
                spec.output_sanitization
                    .sanitize(response.result.as_bytes()),
            ),
        };

        if let Some(sink) = &controls.sink {
            if !stdout.is_empty() {
                // The buffered transport delivers after completion, so
                // there is nothing left to cancel — but a failed sink
                // must surface: the caller would otherwise believe the
                // output was delivered.
                sink(OutputStream::Stdout, stdout.clone()).await?;
            }
        }
        let mut capture = OutputCaptureBuffer::new(controls.retained_output_limit);
        capture.push(&stdout);
        let (retained, stats) = capture.into_parts();

        let mut result = ExecResult::from_shell_status(termination, exit_code, started.elapsed());
        result.stdout = retained;
        let mut streaming = ExecStreamingResult::new(result);
        streaming.streams_separated = false;
        streaming.live_streaming = false;
        streaming.stdout_capture = stats;
        Ok(streaming)
    }

    /// Streaming/stoppable execution through a command session.
    ///
    /// The command runs asynchronously in a dedicated session; logs
    /// follow live with server-side stream separation; the status poll
    /// races the timeout and the stop tokens; and a non-natural end
    /// kills the command by deleting the session. Partial output on
    /// timeout/stop comes from a final log fetch, deduplicated
    /// against what the stream already delivered.
    async fn run_session(
        &self,
        spec: &ExecSpec,
        controls: ExecControls,
    ) -> Result<ExecStreamingResult> {
        let started = Instant::now();
        let sandbox = self
            .client
            .get(&self.sandbox_id)
            .await
            .map_err(|error| daytona_error("fetching sandbox", error))?;

        let mut stdin_file = match &spec.stdin {
            Some(bytes) => Some(StdinFile::create(&self.client, &self.sandbox_id, bytes).await?),
            None => None,
        };

        let mut command = exec_line(&spec.env, &spec.program, &spec.args);
        if let Some(file) = &stdin_file {
            command.push_str(" < ");
            command.push_str(&shell_quote(&file.path));
        }
        let cwd = self.resolve_dir(spec.working_dir.as_deref());
        let program = wrap_session_script(&build_session_script(&cwd, &command));

        let mut session = match Session::create(&self.client, &sandbox).await {
            Ok(session) => session,
            Err(error) => {
                close_stdin(&mut stdin_file).await;
                return Err(error);
            }
        };
        let session_exec = match session.execute(&program).await {
            Ok(result) => result,
            Err(error) => {
                session.close().await;
                close_stdin(&mut stdin_file).await;
                return Err(error);
            }
        };
        let command_id = session_exec.cmd_id.clone();

        // The stream task needs its own service and 'static state.
        let stream_process = match sandbox.process().await {
            Ok(process) => process,
            Err(error) => {
                session.close().await;
                close_stdin(&mut stdin_file).await;
                return Err(daytona_error("connecting to the toolbox", error));
            }
        };
        let stdout_seen = Arc::new(Mutex::new(OutputCaptureBuffer::new(
            controls.retained_output_limit,
        )));
        let stderr_seen = Arc::new(Mutex::new(OutputCaptureBuffer::new(
            controls.retained_output_limit,
        )));
        // Deduplication must compare the provider's raw live and final
        // output, with its own minimum overlap window. The public
        // captures contain sanitized bytes and keep the caller's limit.
        let stdout_raw_seen = Arc::new(Mutex::new(dedup_capture(controls.retained_output_limit)));
        let stderr_raw_seen = Arc::new(Mutex::new(dedup_capture(controls.retained_output_limit)));
        let stdout_sanitizer = Arc::new(Mutex::new(OutputSanitizer::new(spec.output_sanitization)));
        let stderr_sanitizer = Arc::new(Mutex::new(OutputSanitizer::new(spec.output_sanitization)));
        let saw_live = Arc::new(AtomicBool::new(false));
        // A failing sink cancels the execution (the core contract); the
        // token routes the failure into the wait loop below.
        let sink_failed = CancellationToken::new();

        let mut stream_task = tokio::spawn({
            let session_id = session.id().to_owned();
            let command_id = command_id.clone();
            let stdout = StreamSide {
                stream:      OutputStream::Stdout,
                raw_seen:    Arc::clone(&stdout_raw_seen),
                seen:        Arc::clone(&stdout_seen),
                sanitizer:   Arc::clone(&stdout_sanitizer),
                saw_live:    Arc::clone(&saw_live),
                sink:        controls.sink.clone(),
                sink_failed: sink_failed.clone(),
            };
            let stderr = StreamSide {
                stream:      OutputStream::Stderr,
                raw_seen:    Arc::clone(&stderr_raw_seen),
                seen:        Arc::clone(&stderr_seen),
                sanitizer:   Arc::clone(&stderr_sanitizer),
                saw_live:    Arc::clone(&saw_live),
                sink:        controls.sink.clone(),
                sink_failed: sink_failed.clone(),
            };
            async move {
                stream_process
                    .get_session_command_logs_stream(
                        &session_id,
                        &command_id,
                        move |chunk| stdout.clone().deliver(chunk),
                        move |chunk| stderr.clone().deliver(chunk),
                    )
                    .await
            }
        });

        let outcome = match wait_for_completion(
            &session,
            &command_id,
            session_exec.exit_code,
            spec.timeout,
            controls.stop_requested(),
            sink_failed.clone(),
        )
        .await
        {
            Ok(outcome) => outcome,
            Err(error) => {
                stream_task.abort();
                session.close().await;
                close_stdin(&mut stdin_file).await;
                return Err(error);
            }
        };

        // A non-natural end must actively kill the command: deleting
        // the session terminates it and closes the log stream.
        if outcome.termination != Termination::Exited && !session.close().await {
            stream_task.abort();
            close_stdin(&mut stdin_file).await;
            return Err(Error::Incomplete(sandbox_driver::IncompleteOperation::new(
                "Daytona session termination",
            )));
        }

        let stream_clean = match time::timeout(STREAM_DRAIN_GRACE, &mut stream_task).await {
            Ok(Ok(Ok(()))) => true,
            Ok(_) => false,
            Err(_elapsed) => {
                stream_task.abort();
                false
            }
        };
        if !stream_clean {
            if outcome.termination == Termination::Exited {
                tracing::warn!("command log stream ended before a natural exit was drained");
            } else {
                tracing::debug!("command log stream ended during command cancellation");
            }
        }

        let final_logs = match outcome.final_logs {
            Some(logs) => Some(logs),
            None if !stream_clean => session.fetch_logs(&command_id).await,
            None => None,
        };
        let cleanup_confirmed = session.close().await;
        close_stdin(&mut stdin_file).await;
        if !cleanup_confirmed {
            let mut incomplete =
                sandbox_driver::IncompleteOperation::new("Daytona session cleanup");
            incomplete.termination_confirmed = outcome.termination == Termination::Exited;
            incomplete.output_abandoned = !stream_clean;
            return Err(Error::Incomplete(incomplete));
        }

        // The stream and the final fetch overlap arbitrarily; append
        // only what the stream missed, to the buffers and the sink.
        let mut logs_separated = false;
        if let Some(logs) = &final_logs {
            logs_separated = logs.streams_separated;
            for (raw_seen, seen, sanitizer, stream, bytes) in [
                (
                    &stdout_raw_seen,
                    &stdout_seen,
                    &stdout_sanitizer,
                    OutputStream::Stdout,
                    logs.stdout.as_bytes(),
                ),
                (
                    &stderr_raw_seen,
                    &stderr_seen,
                    &stderr_sanitizer,
                    OutputStream::Stderr,
                    logs.stderr.as_bytes(),
                ),
            ] {
                let missing = {
                    let mut raw_seen = raw_seen.lock().await;
                    let missing = missing_suffix(&mut raw_seen, bytes);
                    raw_seen.push(&missing);
                    missing
                };
                let sanitized = sanitizer.lock().await.push(&missing);
                seen.lock().await.push(&sanitized);
                if !sanitized.is_empty() && !sink_failed.is_cancelled() {
                    if let Some(sink) = &controls.sink {
                        if sink(stream, sanitized).await.is_err() {
                            sink_failed.cancel();
                        }
                    }
                }
            }
        }

        for (seen, sanitizer, stream) in [
            (&stdout_seen, &stdout_sanitizer, OutputStream::Stdout),
            (&stderr_seen, &stderr_sanitizer, OutputStream::Stderr),
        ] {
            let final_bytes = sanitizer.lock().await.finish();
            seen.lock().await.push(&final_bytes);
            if !final_bytes.is_empty() && !sink_failed.is_cancelled() {
                if let Some(sink) = &controls.sink {
                    if sink(stream, final_bytes).await.is_err() {
                        sink_failed.cancel();
                    }
                }
            }
        }

        let (stdout_bytes, stdout_stats) = mem::replace(
            &mut *stdout_seen.lock().await,
            OutputCaptureBuffer::new(None),
        )
        .into_parts();
        let (stderr_bytes, stderr_stats) = mem::replace(
            &mut *stderr_seen.lock().await,
            OutputCaptureBuffer::new(None),
        )
        .into_parts();

        let termination = if sink_failed.is_cancelled() {
            Termination::Cancelled
        } else {
            outcome.termination
        };
        // Exit codes are meaningful only for natural exits.
        let exit_code = (termination == Termination::Exited)
            .then_some(outcome.exit_code)
            .flatten();
        let mut result = ExecResult::from_shell_status(termination, exit_code, started.elapsed());
        result.stdout = stdout_bytes;
        result.stderr = stderr_bytes;
        let mut streaming = ExecStreamingResult::new(result);
        streaming.live_streaming = stream_clean || saw_live.load(Ordering::Relaxed);
        streaming.streams_separated = stream_clean || logs_separated;
        streaming.stdout_capture = stdout_stats;
        streaming.stderr_capture = stderr_stats;
        if (!stream_clean && final_logs.is_none()) || sink_failed.is_cancelled() {
            streaming.stdout_capture.truncated = true;
            streaming.stderr_capture.truncated = true;
        }
        Ok(streaming)
    }
}

async fn close_stdin(file: &mut Option<StdinFile>) {
    if let Some(file) = file.as_mut() {
        file.close().await;
    }
}

/// Shared state for one side (stdout or stderr) of the log stream.
#[derive(Clone)]
struct StreamSide {
    stream:      OutputStream,
    raw_seen:    Arc<Mutex<OutputCaptureBuffer>>,
    seen:        Arc<Mutex<OutputCaptureBuffer>>,
    sanitizer:   Arc<Mutex<OutputSanitizer>>,
    saw_live:    Arc<AtomicBool>,
    sink:        Option<OutputSink>,
    sink_failed: CancellationToken,
}

impl StreamSide {
    async fn deliver(self, chunk: String) -> StdResult<(), DaytonaError> {
        let bytes = chunk.into_bytes();
        if bytes.is_empty() {
            return Ok(());
        }
        self.saw_live.store(true, Ordering::Relaxed);
        self.raw_seen.lock().await.push(&bytes);
        let bytes = self.sanitizer.lock().await.push(&bytes);
        self.seen.lock().await.push(&bytes);
        if bytes.is_empty() {
            return Ok(());
        }
        if let Some(sink) = &self.sink {
            if sink(self.stream, bytes).await.is_err() {
                // Cancels the execution via the wait loop; ending the
                // stream here stops further deliveries immediately.
                self.sink_failed.cancel();
                return Err(DaytonaError::general("output sink failed"));
            }
        }
        Ok(())
    }
}

/// Bash source run inside the session's `/bin/bash -c`: pin the working
/// directory, blank `BASH_ENV` (sandbox-level hygiene; the command's own
/// env comes with it, see [`crate::exec_line`]), then run the command in
/// a subshell so its exit status is the script's.
pub(crate) fn build_session_script(cwd: &str, command: &str) -> String {
    [
        format!("cd {} || exit $?", shell_quote(cwd)),
        "export BASH_ENV=''".to_owned(),
        "(".to_owned(),
        command.to_owned(),
        ")".to_owned(),
    ]
    .join("\n")
}

/// The command handed to the session: one quoted `/bin/bash -c` so the
/// caller's source stays inert until Bash evaluates it, and the session
/// shell resumes afterwards to drain logs and record the exit code.
pub(crate) fn wrap_session_script(script: &str) -> String {
    format!("/bin/bash -c {}", shell_quote(script))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_timeout_rounds_sub_second_up() {
        assert_eq!(
            wire_timeout(Some(Duration::from_millis(300))),
            Duration::from_secs(1)
        );
        assert_eq!(
            wire_timeout(Some(Duration::from_secs(10))),
            Duration::from_secs(10)
        );
        assert_eq!(wire_timeout(None), UNBOUNDED_TIMEOUT);
    }

    #[test]
    fn compose_unsets_the_ambient_bash_env_before_the_spec_env() {
        let spec = ExecSpec::bash("true");
        let program = DaytonaTransport::compose(&spec, None);
        // The helper's blank travels like any other spec variable.
        assert_eq!(
            program,
            "unset BASH_ENV\nexec env 'BASH_ENV=' 'bash' '-c' 'true'"
        );
    }

    #[test]
    fn compose_quotes_env_assignments_whole() {
        let spec = ExecSpec::new("true")
            .env_var("X;injected", "a b")
            .env_var("INPUT_INCLUDE-HIDDEN-FILES", "true");
        let program = DaytonaTransport::compose(&spec, None);
        // A metacharacter in a key corrupts nothing: the assignment is one
        // quoted word to `env`, which also admits names that are not shell
        // identifiers.
        assert!(
            program.ends_with("exec env 'INPUT_INCLUDE-HIDDEN-FILES=true' 'X;injected=a b' 'true'"),
            "{program}"
        );
    }

    #[test]
    fn compose_keeps_every_argument_literal() {
        let spec = ExecSpec::new("printf").args(["%s", "$HOME; rm -rf /", "it's"]);
        let program = DaytonaTransport::compose(&spec, None);
        assert!(
            program.ends_with("exec env 'printf' '%s' '$HOME; rm -rf /' 'it'\\''s'"),
            "{program}"
        );
    }

    #[test]
    fn compose_redirects_stdin_from_the_temp_file() {
        let spec = ExecSpec::new("wc").arg("-c");
        let program = DaytonaTransport::compose(&spec, Some("/tmp/.sandbox-driver-stdin-1-2"));
        assert!(
            program.ends_with("exec env 'wc' '-c' < '/tmp/.sandbox-driver-stdin-1-2'"),
            "{program}"
        );
    }

    #[test]
    fn untimed_specs_send_the_unbounded_timeout_explicitly() {
        // An omitted field would let the toolbox kill the command at its
        // 10-second default.
        assert_eq!(wire_timeout(None), UNBOUNDED_TIMEOUT);
        assert_eq!(
            wire_timeout(Some(Duration::from_secs(30))),
            Duration::from_secs(30)
        );
    }

    #[test]
    fn unbounded_timeout_survives_the_wire_conversion() {
        // The SDK converts with `as_secs() as i32`; a value past i32::MAX
        // would truncate into garbage.
        assert!(i32::try_from(UNBOUNDED_TIMEOUT.as_secs()).is_ok());
    }
}
