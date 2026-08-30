use std::collections::BTreeMap;
use std::result::Result as StdResult;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use std::{mem, process};

use async_trait::async_trait;
use daytona_sdk::{DaytonaError, ExecuteCommandOptions, FileSystemService, ProcessService};
use sandbox_driver::{
    Exec, ExecControls, ExecResult, ExecSpec, ExecStreamingResult, OutputCaptureBuffer, OutputSink,
    OutputStream, Result, Termination,
};
use tokio::runtime::Handle;
use tokio::sync::{Mutex, OnceCell};
use tokio::time;
use tokio_util::sync::CancellationToken;

use crate::session::{Session, missing_suffix, wait_for_completion};
use crate::{DaytonaClient, daytona_error, is_server_timeout, shell_quote};

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

/// The server-side timeout for a spec: its own, or the unbounded
/// stand-in — never an omitted field.
fn wire_timeout(spec_timeout: Option<Duration>) -> Duration {
    spec_timeout.unwrap_or(UNBOUNDED_TIMEOUT)
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
        let sandbox = client
            .get(sandbox_id)
            .await
            .map_err(|error| daytona_error("fetching sandbox", &error))?;
        let fs = sandbox
            .fs()
            .await
            .map_err(|error| daytona_error("connecting to the toolbox", &error))?;
        // Random nonce plus host pid: unique even across concurrent
        // execs in one process, so a stale file from a crashed driver
        // can never feed a later command.
        let nonce: u64 = rand::random();
        let path = format!("/tmp/.sandbox-driver-stdin-{}-{nonce:016x}", process::id());
        fs.upload_file_bytes(&path, bytes)
            .await
            .map_err(|error| daytona_error("uploading exec stdin", &error))?;
        Ok(Self { fs: Some(fs), path })
    }

    /// Bounded, best-effort deletion. Failures are swallowed: cleanup
    /// must never fail a command that already ran.
    async fn close(&mut self) {
        let Some(fs) = self.fs.as_ref() else {
            return;
        };
        let _ = time::timeout(STDIN_CLEANUP_TIMEOUT, fs.delete_file(&self.path, false)).await;
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
                let _ = time::timeout(STDIN_CLEANUP_TIMEOUT, fs.delete_file(&path, false)).await;
            });
        }
    }
}

/// Command execution through the Daytona toolbox, on two transports.
///
/// A plain run uses the one-shot `execute` endpoint: combined output
/// after completion (`streams_separated: false`, `live_streaming:
/// false`, stderr empty) at one API call. A run with a sink or cancel
/// token uses a command session instead: logs stream live with
/// server-side stdout/stderr separation, cancellation and timeouts
/// kill the command by deleting its session, and partial output
/// survives a timeout via a final log fetch. On both transports the
/// Bash contract is enforced by wrapping the command in
/// `/bin/bash -c …` with `BASH_ENV` blanked; environment variables
/// cross as `export` statements because the API's `envs` field is not
/// reliably applied.
pub struct DaytonaExec {
    client:      DaytonaClient,
    sandbox_id:  String,
    working_dir: String,
    process:     OnceCell<ProcessService>,
}

impl DaytonaExec {
    pub(crate) fn new(client: DaytonaClient, sandbox_id: String, working_dir: String) -> Self {
        Self {
            client,
            sandbox_id,
            working_dir,
            process: OnceCell::new(),
        }
    }

    async fn process(&self) -> Result<&ProcessService> {
        self.process
            .get_or_try_init(|| async {
                let sandbox = self
                    .client
                    .get(&self.sandbox_id)
                    .await
                    .map_err(|error| daytona_error("fetching sandbox", &error))?;
                sandbox
                    .process()
                    .await
                    .map_err(|error| daytona_error("connecting to the toolbox", &error))
            })
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
        let mut program = String::from("unset BASH_ENV\n");
        for (key, value) in &spec.env {
            // The unset above runs first, so a spec-provided BASH_ENV
            // would re-arm startup-file injection into the inner bash;
            // the exec contract strips it on every transport.
            if key == "BASH_ENV" {
                continue;
            }
            // Quote the key as well as the value: a malformed key must
            // corrupt nothing but its own export.
            program.push_str("export ");
            program.push_str(&shell_quote(key));
            program.push('=');
            program.push_str(&shell_quote(value));
            program.push('\n');
        }
        program.push_str("exec /bin/bash -c ");
        program.push_str(&shell_quote(&spec.command));
        // Write-then-EOF as a file redirection on the inner bash.
        if let Some(path) = stdin_path {
            program.push_str(" < ");
            program.push_str(&shell_quote(path));
        }
        program
    }
}

#[async_trait]
impl Exec for DaytonaExec {
    async fn run(&self, spec: &ExecSpec) -> Result<ExecResult> {
        let streaming = self.run_streaming(spec, ExecControls::default()).await?;
        Ok(streaming.result)
    }

    async fn run_streaming(
        &self,
        spec: &ExecSpec,
        controls: ExecControls,
    ) -> Result<ExecStreamingResult> {
        // Sessions cost three extra API calls, so plain buffered runs —
        // every derived fs/search/git operation — keep the one-shot
        // endpoint; only a sink or cancel token needs the session
        // transport.
        if controls.sink.is_some() || controls.cancel.is_some() {
            return self.run_session(spec, controls).await;
        }
        self.run_buffered(spec, &controls).await
    }
}

impl DaytonaExec {
    async fn run_buffered(
        &self,
        spec: &ExecSpec,
        controls: &ExecControls,
    ) -> Result<ExecStreamingResult> {
        let started = Instant::now();
        let process = self.process().await?;
        let mut stdin_file = match &spec.stdin {
            Some(bytes) => Some(StdinFile::create(&self.client, &self.sandbox_id, bytes).await?),
            None => None,
        };
        let options = ExecuteCommandOptions {
            cwd:     Some(self.resolve_dir(spec.working_dir.as_deref())),
            env:     None,
            timeout: Some(wire_timeout(spec.timeout)),
        };
        let program = Self::compose(spec, stdin_file.as_ref().map(|file| file.path.as_str()));
        let call = process.execute_command(&program, options);

        // A server-side timeout comes back as a 408 error rather than a
        // response, and a client-side deadline elapses as None; both mean
        // the command was killed for exceeding its timeout.
        let response = match spec.timeout {
            Some(timeout) => match time::timeout(timeout + TIMEOUT_GRACE, call).await {
                Ok(Ok(response)) => Ok(Some(response)),
                Ok(Err(error)) if is_server_timeout(&error) => Ok(None),
                Ok(Err(error)) => Err(daytona_error("executing command", &error)),
                Err(_) => Ok(None),
            },
            None => match call.await {
                Ok(response) => Ok(Some(response)),
                // The unbounded stand-in is still finite server-side, so
                // its expiry is a timeout kill, not a provider failure.
                Err(error) if is_server_timeout(&error) => Ok(None),
                Err(error) => Err(daytona_error("executing command", &error)),
            },
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
                Some(response.exit_code),
                response.result.into_bytes(),
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

        let mut result = ExecResult::new(termination, exit_code, started.elapsed());
        result.stdout = retained;
        let mut streaming = ExecStreamingResult::new(result);
        streaming.streams_separated = false;
        streaming.live_streaming = false;
        streaming.stdout_capture = stats;
        Ok(streaming)
    }

    /// Streaming/cancellable execution through a command session.
    ///
    /// The command runs asynchronously in a dedicated session; logs
    /// follow live with server-side stream separation; the status poll
    /// races the timeout and the cancel token; and a non-natural end
    /// kills the command by deleting the session. Partial output on
    /// timeout/cancel comes from a final log fetch, deduplicated
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
            .map_err(|error| daytona_error("fetching sandbox", &error))?;

        let mut stdin_file = match &spec.stdin {
            Some(bytes) => Some(StdinFile::create(&self.client, &self.sandbox_id, bytes).await?),
            None => None,
        };

        let command = match &stdin_file {
            Some(file) => format!("(\n{}\n) < {}", spec.command, shell_quote(&file.path)),
            None => spec.command.clone(),
        };
        let cwd = self.resolve_dir(spec.working_dir.as_deref());
        let program = wrap_session_script(&build_session_script(&cwd, &spec.env, &command));

        let mut session = match Session::create(&sandbox).await {
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
                return Err(daytona_error("connecting to the toolbox", &error));
            }
        };
        let stdout_seen = Arc::new(Mutex::new(OutputCaptureBuffer::new(
            controls.retained_output_limit,
        )));
        let stderr_seen = Arc::new(Mutex::new(OutputCaptureBuffer::new(
            controls.retained_output_limit,
        )));
        let saw_live = Arc::new(AtomicBool::new(false));
        // A failing sink cancels the execution (the core contract); the
        // token routes the failure into the wait loop below.
        let sink_failed = CancellationToken::new();

        let mut stream_task = tokio::spawn({
            let session_id = session.id().to_owned();
            let command_id = command_id.clone();
            let stdout = StreamSide {
                stream:      OutputStream::Stdout,
                seen:        Arc::clone(&stdout_seen),
                saw_live:    Arc::clone(&saw_live),
                sink:        controls.sink.clone(),
                sink_failed: sink_failed.clone(),
            };
            let stderr = StreamSide {
                stream:      OutputStream::Stderr,
                seen:        Arc::clone(&stderr_seen),
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
            controls.cancel.clone(),
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
        if outcome.termination != Termination::Exited {
            session.close().await;
        }

        let stream_clean = match time::timeout(STREAM_DRAIN_GRACE, &mut stream_task).await {
            Ok(Ok(Ok(()))) => true,
            Ok(_) => false,
            Err(_elapsed) => {
                stream_task.abort();
                false
            }
        };

        let final_logs = match outcome.final_logs {
            Some(logs) => Some(logs),
            None => session.fetch_logs(&command_id).await,
        };
        session.close().await;
        close_stdin(&mut stdin_file).await;

        // The stream and the final fetch overlap arbitrarily; append
        // only what the stream missed, to the buffers and the sink.
        let mut logs_separated = false;
        if let Some(logs) = &final_logs {
            logs_separated = logs.streams_separated;
            for (buffer, stream, bytes) in [
                (&stdout_seen, OutputStream::Stdout, logs.stdout.as_bytes()),
                (&stderr_seen, OutputStream::Stderr, logs.stderr.as_bytes()),
            ] {
                let missing = {
                    let mut seen = buffer.lock().await;
                    let missing = missing_suffix(&mut seen, bytes);
                    seen.push(&missing);
                    missing
                };
                if !missing.is_empty() && !sink_failed.is_cancelled() {
                    if let Some(sink) = &controls.sink {
                        sink(stream, missing).await?;
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
        let mut result = ExecResult::new(termination, exit_code, started.elapsed());
        result.stdout = stdout_bytes;
        result.stderr = stderr_bytes;
        let mut streaming = ExecStreamingResult::new(result);
        streaming.live_streaming = stream_clean || saw_live.load(Ordering::Relaxed);
        streaming.streams_separated = stream_clean || logs_separated;
        streaming.stdout_capture = stdout_stats;
        streaming.stderr_capture = stderr_stats;
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
    seen:        Arc<Mutex<OutputCaptureBuffer>>,
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
        self.seen.lock().await.push(&bytes);
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
/// directory, blank `BASH_ENV` (overriding any caller value), export
/// the spec env with both halves quoted, then run the command in a
/// subshell so its exit status is the script's.
fn build_session_script(cwd: &str, env: &BTreeMap<String, String>, command: &str) -> String {
    let mut lines = vec![format!("cd {} || exit $?", shell_quote(cwd))];
    lines.push("export BASH_ENV=''".to_owned());
    for (key, value) in env {
        if key == "BASH_ENV" {
            continue;
        }
        lines.push(format!(
            "export {}={}",
            shell_quote(key),
            shell_quote(value)
        ));
    }
    lines.push("(".to_owned());
    lines.push(command.to_owned());
    lines.push(")".to_owned());
    lines.join("\n")
}

/// The command handed to the session: one quoted `/bin/bash -c` so the
/// caller's source stays inert until Bash evaluates it, and the session
/// shell resumes afterwards to drain logs and record the exit code.
fn wrap_session_script(script: &str) -> String {
    format!("/bin/bash -c {}", shell_quote(script))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compose_strips_a_spec_provided_bash_env() {
        let spec = ExecSpec::new("true").env_var("BASH_ENV", "/tmp/startup");
        let program = DaytonaExec::compose(&spec, None);
        assert!(program.starts_with("unset BASH_ENV\n"));
        assert!(!program.contains("export BASH_ENV"));
    }

    #[test]
    fn compose_quotes_env_keys_and_values() {
        let spec = ExecSpec::new("true").env_var("X;injected", "a b");
        let program = DaytonaExec::compose(&spec, None);
        // A metacharacter in a key corrupts only its own export instead
        // of splicing extra shell before the command.
        assert!(program.contains("export 'X;injected'='a b'\n"), "{program}");
    }

    #[test]
    fn compose_redirects_stdin_from_the_temp_file() {
        let spec = ExecSpec::new("wc -c");
        let program = DaytonaExec::compose(&spec, Some("/tmp/.sandbox-driver-stdin-1-2"));
        assert!(
            program.ends_with("exec /bin/bash -c 'wc -c' < '/tmp/.sandbox-driver-stdin-1-2'"),
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
