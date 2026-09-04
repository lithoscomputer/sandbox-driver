use std::collections::BTreeMap;
use std::pin::Pin;
use std::result::Result as StdResult;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use std::{future, io, process};

use async_trait::async_trait;
use bollard::Docker;
use bollard::container::LogOutput;
use bollard::errors::Error as DockerApiError;
use bollard::exec::{CreateExecOptions, StartExecOptions, StartExecResults};
use futures_util::StreamExt;
use sandbox_driver::{
    Error, Exec, ExecControls, ExecResult, ExecSpec, ExecStreamingResult, OutputCaptureBuffer,
    OutputSanitizer, OutputSink, OutputStream, ProviderError, ProviderKind, Result, SpawnSpec,
    StderrTail, StdinSource, StdioProcess, StdioProcessHandle, Termination,
};
use tokio::io::{AsyncWrite, AsyncWriteExt, copy, duplex};
use tokio::time;

/// The container-side interpreter the Bash contract requires.
const CONTAINER_BASH: &str = "/bin/bash";
pub(crate) const BASH_ENV_VAR: &str = "BASH_ENV";
/// Grace period for draining output after a stop request. Must exceed
/// the watcher's poll interval plus [`TERM_GRACE_SECONDS`].
const KILL_DRAIN_GRACE: Duration = Duration::from_secs(10);
/// Bound on retrying transient `inspect_exec` failures in stdio `wait`
/// before giving up with `Termination::Unknown`: an end that was never
/// observed is reported only when the daemon stays unreachable for the
/// whole window.
const WAIT_INSPECT_RETRY: Duration = Duration::from_secs(10);
/// The in-container watcher's poll interval for the stop file.
const STOP_POLL_SLEEP_SECONDS: &str = "0.1";
/// Grace between the watcher's SIGTERM and SIGKILL so processes can run
/// traps, flush output, and release locks. The wrapper's `wait` returns
/// as soon as the process exits, so a generous grace costs nothing on
/// the normal path.
const TERM_GRACE_SECONDS: &str = "2";

pub(crate) fn docker_error(context: &str, error: DockerApiError) -> Error {
    let kind = ProviderKind::try_new("docker").expect("static kind is valid");
    let status_code = match &error {
        DockerApiError::DockerResponseServerError { status_code, .. } => Some(*status_code),
        _ => None,
    };
    let mut provider = ProviderError::with_source(kind, context, error);
    if let Some(status_code) = status_code {
        provider.code = Some(status_code.to_string());
        provider.retryable = status_code >= 500;
    }
    Error::Provider(provider)
}

pub(crate) fn is_not_found(error: &DockerApiError) -> bool {
    matches!(error, DockerApiError::DockerResponseServerError {
        status_code: 404,
        ..
    })
}

pub(crate) fn is_not_modified(error: &DockerApiError) -> bool {
    matches!(error, DockerApiError::DockerResponseServerError {
        status_code: 304,
        ..
    })
}

pub(crate) fn is_conflict(error: &DockerApiError) -> bool {
    matches!(error, DockerApiError::DockerResponseServerError {
        status_code: 409,
        ..
    })
}

pub(crate) fn tolerate_not_modified(
    outcome: StdResult<(), DockerApiError>,
    context: &str,
) -> Result<()> {
    match outcome {
        Ok(()) => Ok(()),
        Err(error) if is_not_modified(&error) || is_not_found(&error) => Ok(()),
        Err(error) => Err(docker_error(context, error)),
    }
}

/// Writes stdin then closes it for EOF. A command that stops reading its
/// input (`head -1`) disconnecting the pipe is normal; any other failure
/// means the command saw truncated input and must not pass silently.
/// Whether a stdin write failed because the reader disconnected — normal
/// for a command like `head -1` that stops reading.
fn is_disconnect(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::BrokenPipe
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
    )
}

async fn write_stdin(mut input: Pin<Box<dyn AsyncWrite + Send>>, bytes: Vec<u8>) -> Result<()> {
    if let Err(error) = input.write_all(&bytes).await {
        if is_disconnect(&error) {
            return Ok(());
        }
        return Err(Error::io("writing exec stdin", error));
    }
    if let Err(error) = input.shutdown().await {
        if is_disconnect(&error) {
            return Ok(());
        }
        return Err(Error::io("closing exec stdin", error));
    }
    Ok(())
}

/// Copies a streamed source into the exec stdin, then closes it for EOF.
async fn stream_stdin_into(
    mut input: Pin<Box<dyn AsyncWrite + Send>>,
    source: StdinSource,
) -> Result<()> {
    let Some(mut reader) = source.take() else {
        let _ = input.shutdown().await;
        return Ok(());
    };
    if let Err(error) = copy(&mut reader, &mut input).await {
        if is_disconnect(&error) {
            return Ok(());
        }
        return Err(Error::io("streaming exec stdin", error));
    }
    if let Err(error) = input.shutdown().await {
        if is_disconnect(&error) {
            return Ok(());
        }
        return Err(Error::io("closing exec stdin", error));
    }
    Ok(())
}

pub(crate) fn shell_quote(value: &str) -> String {
    let mut quoted = String::with_capacity(value.len() + 2);
    quoted.push('\'');
    for c in value.chars() {
        if c == '\'' {
            quoted.push_str("'\\''");
        } else {
            quoted.push(c);
        }
    }
    quoted.push('\'');
    quoted
}

/// Command execution inside one container.
///
/// Docker cannot kill an exec instance, so every command runs under a
/// wrapper that puts it in its own session and pairs it with an
/// in-container watcher; timeout and cancellation request a stop by
/// creating a stop file through a second exec, and the watcher kills
/// the process group (SIGTERM, grace, SIGKILL) whenever the stop lands
/// — even before the command starts. The wrapper's `wait` forwards the
/// child's exit code.
pub struct DockerExec {
    docker:       Docker,
    container_id: String,
    working_dir:  String,
    base_env:     BTreeMap<String, String>,
    exec_counter: AtomicU64,
}

impl DockerExec {
    pub(crate) fn new(
        docker: Docker,
        container_id: String,
        working_dir: String,
        base_env: BTreeMap<String, String>,
    ) -> Self {
        Self {
            docker,
            container_id,
            working_dir,
            base_env,
            exec_counter: AtomicU64::new(0),
        }
    }

    fn env_entries(&self, extra: &BTreeMap<String, String>) -> Vec<String> {
        let mut entries: Vec<String> = self
            .base_env
            .iter()
            .chain(extra)
            .filter(|(key, _)| key.as_str() != BASH_ENV_VAR)
            .map(|(key, value)| format!("{key}={value}"))
            .collect();
        entries.push(format!("{BASH_ENV_VAR}="));
        entries
    }

    /// Resolves a relative working directory against the sandbox
    /// working directory, matching the fs facet — Docker rejects a
    /// relative exec `Cwd` outright.
    fn resolve_dir(&self, dir: Option<&str>) -> String {
        match dir {
            None => self.working_dir.clone(),
            Some(dir) if dir.starts_with('/') => dir.to_owned(),
            Some(dir) => format!("{}/{}", self.working_dir.trim_end_matches('/'), dir),
        }
    }

    /// Allocates a unique stop-file/pid-file pair for one exec. The
    /// nanosecond nonce keeps paths from colliding across driver
    /// restarts (containers outlive drivers, host pids recycle, and the
    /// counter restarts at zero), so a stale control file can never
    /// misdirect a stop.
    fn control_paths(&self) -> (String, String) {
        let count = self.exec_counter.fetch_add(1, Ordering::Relaxed);
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or_default();
        let prefix = format!(
            "/tmp/.sandbox-driver/exec-{}-{nonce}-{count}",
            process::id()
        );
        (format!("{prefix}.stop"), format!("{prefix}.pid"))
    }

    /// Wraps a user command so a stop request is honored at any point.
    ///
    /// An in-container watcher polls for the stop file, so a stop that
    /// lands before the pid file exists — or before the command starts
    /// at all — still takes effect. The watcher SIGTERMs the process
    /// group, waits [`TERM_GRACE_SECONDS`] for a graceful exit, then
    /// SIGKILLs. Control files are cleared before the command starts
    /// and removed on exit.
    fn wrapped(
        user_command: &str,
        stop_file: &str,
        pid_file: &str,
        forward_stdin: bool,
        grace_seconds: u64,
    ) -> String {
        let quoted_cmd = shell_quote(user_command);
        let stop_file = shell_quote(stop_file);
        let pid_file = shell_quote(pid_file);
        let grace = grace_seconds.to_string();
        let (save_stdin, stdin_redirect, close_stdin) = if forward_stdin {
            ("exec 3<&0\n", "<&3", "exec 3<&-\n")
        } else {
            ("", "< /dev/null", "")
        };
        // The stop file is empty for a polite cancel and holds `kill` for an
        // immediate SIGKILL. The watcher reads it to pick the ladder: TERM,
        // grace, KILL for a cancel; straight to KILL for a kill.
        format!(
            "mkdir -p /tmp/.sandbox-driver\n\
             if ! command -v setsid >/dev/null 2>&1; then\n\
               echo 'sandbox-driver: the container image must provide setsid' >&2\n\
               exit 127\n\
             fi\n\
             stop_file={stop_file}\n\
             pid_file={pid_file}\n\
             {save_stdin}rm -f \"$pid_file\"\n\
             if [ -e \"$stop_file\" ]; then\n\
               mode=$(cat \"$stop_file\" 2>/dev/null)\n\
               rm -f \"$stop_file\"\n\
               if [ \"$mode\" = kill ]; then exit 137; fi\n\
               exit 143\n\
             fi\n\
             (\n\
               while [ ! -e \"$stop_file\" ]; do sleep {STOP_POLL_SLEEP_SECONDS}; done\n\
               while [ ! -s \"$pid_file\" ]; do sleep {STOP_POLL_SLEEP_SECONDS}; done\n\
               child=$(cat \"$pid_file\")\n\
               mode=$(cat \"$stop_file\" 2>/dev/null)\n\
               if [ \"$mode\" != kill ]; then\n\
                 kill -TERM \"-$child\" 2>/dev/null || kill -TERM \"$child\" 2>/dev/null || true\n\
                 sleep {grace}\n\
               fi\n\
               kill -KILL \"-$child\" 2>/dev/null || kill -KILL \"$child\" 2>/dev/null || true\n\
             ) & watcher=$!\n\
             setsid {CONTAINER_BASH} -c {quoted_cmd} {stdin_redirect} &\n\
             child=$!\n\
             {close_stdin}printf '%s' \"$child\" > \"$pid_file\"\n\
             wait \"$child\"\n\
             status=$?\n\
             kill \"$watcher\" 2>/dev/null || true\n\
             wait \"$watcher\" 2>/dev/null || true\n\
             rm -f \"$stop_file\" \"$pid_file\"\n\
             exit \"$status\""
        )
    }

    /// Requests a stop by creating the stop file the in-container
    /// watcher polls for; a stop that arrives before the command starts
    /// is honored by the wrapper's pre-check. Runs from `/` — the exec
    /// being stopped may have removed the working directory the
    /// container would otherwise start this one in — with a blank
    /// `BASH_ENV`, and reports failure: a stop that could not be
    /// requested must never masquerade as a kill.
    async fn request_stop(&self, stop_file: &str) -> Result<()> {
        self.write_stop(stop_file, "").await
    }

    /// Requests an immediate SIGKILL by writing `kill` into the stop file.
    async fn request_kill(&self, stop_file: &str) -> Result<()> {
        self.write_stop(stop_file, "kill").await
    }

    async fn write_stop(&self, stop_file: &str, mode: &str) -> Result<()> {
        let command = format!(
            "mkdir -p /tmp/.sandbox-driver && printf '%s' {} > {}",
            shell_quote(mode),
            shell_quote(stop_file)
        );
        let options = CreateExecOptions {
            cmd: Some(vec![CONTAINER_BASH.to_owned(), "-c".to_owned(), command]),
            attach_stdout: Some(true),
            attach_stderr: Some(true),
            tty: Some(false),
            working_dir: Some("/".to_owned()),
            env: Some(vec![format!("{BASH_ENV_VAR}=")]),
            ..Default::default()
        };
        let exec = self
            .docker
            .create_exec(&self.container_id, options)
            .await
            .map_err(|error| docker_error("creating stop-request exec", error))?;
        let start = self
            .docker
            .start_exec(&exec.id, None::<StartExecOptions>)
            .await
            .map_err(|error| docker_error("starting stop-request exec", error))?;
        if let StartExecResults::Attached { mut output, .. } = start {
            // Drain to completion so the exit code below is final.
            while let Some(chunk) = output.next().await {
                if let Err(error) = chunk {
                    let error = docker_error("reading stop request output", error);
                    tracing::warn!(
                        provider_kind = "docker",
                        sandbox_id = %self.container_id,
                        error = %error,
                        "stop request output stream failed"
                    );
                    break;
                }
            }
        }
        match self.exit_code(&exec.id).await? {
            None | Some(0) => Ok(()),
            Some(code) => Err(Error::io(
                "requesting exec stop",
                io::Error::other(format!("stop request exited {code}")),
            )),
        }
    }

    async fn exit_code(&self, exec_id: &str) -> Result<Option<i32>> {
        let inspect = self
            .docker
            .inspect_exec(exec_id)
            .await
            .map_err(|error| docker_error("inspecting exec", error))?;
        Ok(inspect.exit_code.and_then(|code| i32::try_from(code).ok()))
    }
}

#[async_trait]
impl Exec for DockerExec {
    async fn run(&self, spec: &ExecSpec) -> Result<ExecResult> {
        let streaming = self.run_streaming(spec, ExecControls::default()).await?;
        Ok(streaming.result)
    }

    #[tracing::instrument(
        skip_all,
        fields(
            provider_kind = "docker",
            sandbox_id = %self.container_id,
            has_stdin = spec.stdin.is_some()
        ),
        err
    )]
    async fn run_streaming(
        &self,
        spec: &ExecSpec,
        controls: ExecControls,
    ) -> Result<ExecStreamingResult> {
        let started = Instant::now();
        let (stop_file, pid_file) = self.control_paths();
        let grace_seconds = controls.grace.map_or_else(
            || TERM_GRACE_SECONDS.parse().unwrap_or(2),
            |d| d.as_secs().max(1),
        );
        let stream_stdin = controls.stdin.clone();
        let has_stdin = spec.stdin.is_some() || stream_stdin.is_some();
        let wrapper = Self::wrapped(
            &spec.command,
            &stop_file,
            &pid_file,
            has_stdin,
            grace_seconds,
        );

        let working_dir = self.resolve_dir(spec.working_dir.as_deref());
        let options = CreateExecOptions {
            attach_stdin: Some(has_stdin),
            attach_stdout: Some(true),
            attach_stderr: Some(true),
            tty: Some(false),
            cmd: Some(vec![CONTAINER_BASH.to_owned(), "-c".to_owned(), wrapper]),
            working_dir: Some(working_dir),
            env: Some(self.env_entries(&spec.env)),
            ..Default::default()
        };
        let exec = self
            .docker
            .create_exec(&self.container_id, options)
            .await
            .map_err(|error| docker_error("creating exec", error))?;
        let start = self
            .docker
            .start_exec(&exec.id, None::<StartExecOptions>)
            .await
            .map_err(|error| docker_error("starting exec", error))?;
        let StartExecResults::Attached { mut output, input } = start else {
            return Err(docker_error("starting exec", DockerApiError::IOError {
                err: io::Error::other("exec started detached"),
            }));
        };

        let stdin_task = match (stream_stdin, spec.stdin.clone()) {
            (Some(source), _) => Some(tokio::spawn(stream_stdin_into(input, source))),
            (None, Some(bytes)) => Some(tokio::spawn(write_stdin(input, bytes))),
            (None, None) => {
                drop(input);
                None
            }
        };

        let mut stdout_capture = OutputCaptureBuffer::new(controls.retained_output_limit);
        let mut stderr_capture = OutputCaptureBuffer::new(controls.retained_output_limit);
        let mut stdout_sanitizer = OutputSanitizer::new(spec.output_sanitization);
        let mut stderr_sanitizer = OutputSanitizer::new(spec.output_sanitization);
        let sink: Option<&OutputSink> = controls.sink.as_ref();

        let mut termination = Termination::Exited;
        let mut kill_fired = false;
        let mut drain_deadline: Option<Instant> = None;
        let mut stream_error: Option<DockerApiError> = None;
        loop {
            let cancel = controls.cancel.clone();
            let cancelled = async {
                match &cancel {
                    Some(token) if !kill_fired => token.cancelled().await,
                    _ => future::pending().await,
                }
            };
            let kill = controls.kill.clone();
            let killed = async {
                match &kill {
                    Some(token) if !kill_fired => token.cancelled().await,
                    _ => future::pending().await,
                }
            };
            let timeout = async {
                match spec.timeout {
                    Some(timeout) if !kill_fired => {
                        let elapsed = started.elapsed();
                        if elapsed >= timeout {
                            return;
                        }
                        time::sleep(timeout.saturating_sub(elapsed)).await;
                    }
                    _ => future::pending().await,
                }
            };
            let drain_timeout = async {
                match drain_deadline {
                    Some(deadline) => time::sleep_until(deadline.into()).await,
                    None => future::pending().await,
                }
            };

            tokio::select! {
                chunk = output.next() => match chunk {
                    None => break,
                    // A transport failure mid-stream means output is
                    // incomplete; it must surface as an error, never as
                    // a clean exit with truncated output.
                    Some(Err(error)) => {
                        stream_error = Some(error);
                        break;
                    }
                    Some(Ok(LogOutput::StdOut { message } | LogOutput::Console { message })) => {
                        let message = stdout_sanitizer.push(&message);
                        stdout_capture.push(&message);
                        if !message.is_empty() {
                            if let Some(sink) = sink {
                                if sink(OutputStream::Stdout, message).await.is_err()
                                    && !kill_fired
                                {
                                    termination = Termination::Cancelled;
                                    kill_fired = true;
                                    drain_deadline = Some(Instant::now() + KILL_DRAIN_GRACE);
                                    self.request_stop(&stop_file).await?;
                                }
                            }
                        }
                    }
                    Some(Ok(LogOutput::StdErr { message })) => {
                        let message = stderr_sanitizer.push(&message);
                        stderr_capture.push(&message);
                        if !message.is_empty() {
                            if let Some(sink) = sink {
                                if sink(OutputStream::Stderr, message).await.is_err()
                                    && !kill_fired
                                {
                                    termination = Termination::Cancelled;
                                    kill_fired = true;
                                    drain_deadline = Some(Instant::now() + KILL_DRAIN_GRACE);
                                    self.request_stop(&stop_file).await?;
                                }
                            }
                        }
                    }
                    Some(Ok(_)) => {}
                },
                () = cancelled => {
                    termination = Termination::Cancelled;
                    kill_fired = true;
                    drain_deadline = Some(Instant::now() + KILL_DRAIN_GRACE);
                    self.request_stop(&stop_file).await?;
                }
                () = killed => {
                    termination = Termination::Killed;
                    kill_fired = true;
                    drain_deadline = Some(Instant::now() + KILL_DRAIN_GRACE);
                    self.request_kill(&stop_file).await?;
                }
                () = timeout => {
                    termination = Termination::TimedOut;
                    kill_fired = true;
                    drain_deadline = Some(Instant::now() + KILL_DRAIN_GRACE);
                    self.request_stop(&stop_file).await?;
                }
                () = drain_timeout => break,
            }
        }

        for (stream, sanitizer, capture) in [
            (
                OutputStream::Stdout,
                &mut stdout_sanitizer,
                &mut stdout_capture,
            ),
            (
                OutputStream::Stderr,
                &mut stderr_sanitizer,
                &mut stderr_capture,
            ),
        ] {
            let bytes = sanitizer.finish();
            capture.push(&bytes);
            if !bytes.is_empty() {
                if let Some(sink) = sink {
                    if sink(stream, bytes).await.is_err() {
                        termination = Termination::Cancelled;
                    }
                }
            }
        }

        if let Some(stdin_task) = stdin_task {
            // The command is done, so unwritten stdin bytes are
            // unwanted; abort instead of joining unbounded.
            stdin_task.abort();
            match stdin_task.await {
                Ok(result) => result?,
                Err(join_error) if join_error.is_cancelled() => {}
                Err(join_error) => {
                    return Err(Error::io(
                        "exec stdin writer task",
                        io::Error::other(join_error),
                    ));
                }
            }
        }
        if let Some(error) = stream_error {
            return Err(docker_error("reading exec output", error));
        }
        let exit_code = self.exit_code(&exec.id).await?;
        let (stdout_bytes, stdout_stats) = stdout_capture.into_parts();
        let (stderr_bytes, stderr_stats) = stderr_capture.into_parts();
        // The wrapper reports a signalled child as the shell's `128 + N`.
        // Surface the signal, and for a natural exit leave the code intact
        // so a step that deliberately exits 137 is not misread.
        let signal = match (termination, exit_code) {
            (Termination::Exited, Some(code)) if (129..=192).contains(&code) => Some(code - 128),
            _ => None,
        };
        let mut result = ExecResult::new(termination, exit_code, started.elapsed());
        result.signal = signal;
        result.stdout = stdout_bytes;
        result.stderr = stderr_bytes;
        let mut streaming = ExecStreamingResult::new(result);
        streaming.streams_separated = true;
        streaming.live_streaming = true;
        streaming.stdout_capture = stdout_stats;
        streaming.stderr_capture = stderr_stats;
        Ok(streaming)
    }

    #[tracing::instrument(
        skip_all,
        fields(provider_kind = "docker", sandbox_id = %self.container_id),
        err
    )]
    async fn spawn_stdio(&self, spec: &SpawnSpec) -> Result<StdioProcess> {
        let (stop_file, pid_file) = self.control_paths();
        let grace_seconds = TERM_GRACE_SECONDS.parse().unwrap_or(2);
        let wrapper = Self::wrapped(&spec.command, &stop_file, &pid_file, true, grace_seconds);
        let working_dir = self.resolve_dir(spec.working_dir.as_deref());
        let options = CreateExecOptions {
            attach_stdin: Some(true),
            attach_stdout: Some(true),
            attach_stderr: Some(true),
            tty: Some(false),
            cmd: Some(vec![CONTAINER_BASH.to_owned(), "-c".to_owned(), wrapper]),
            working_dir: Some(working_dir),
            env: Some(self.env_entries(&spec.env)),
            ..Default::default()
        };
        let exec = self
            .docker
            .create_exec(&self.container_id, options)
            .await
            .map_err(|error| docker_error("creating stdio exec", error))?;
        let start = self
            .docker
            .start_exec(&exec.id, None::<StartExecOptions>)
            .await
            .map_err(|error| docker_error("starting stdio exec", error))?;
        let StartExecResults::Attached { mut output, input } = start else {
            return Err(docker_error(
                "starting stdio exec",
                DockerApiError::IOError {
                    err: io::Error::other("exec started detached"),
                },
            ));
        };

        // Demux the attached stream into a stdout pipe and a stderr tail.
        let (stdout_writer, stdout_reader) = duplex(64 * 1024);
        let stderr_tail = StderrTail::default();
        let tail = stderr_tail.clone();
        let sandbox_id = self.container_id.clone();
        tokio::spawn(async move {
            let mut stdout_writer = stdout_writer;
            loop {
                match output.next().await {
                    None => break,
                    // Make a transport failure visible in the diagnostic
                    // tail instead of ending the stream silently.
                    Some(Err(error)) => {
                        let diagnostic = error.to_string();
                        let error = docker_error("reading stdio output", error);
                        tracing::warn!(
                            provider_kind = "docker",
                            sandbox_id = %sandbox_id,
                            error = %error,
                            "stdio output stream failed"
                        );
                        tail.push(
                            format!("sandbox-driver: stdio output stream error: {diagnostic}\n")
                                .as_bytes(),
                        );
                        break;
                    }
                    Some(Ok(LogOutput::StdOut { message } | LogOutput::Console { message })) => {
                        if let Err(error) = stdout_writer.write_all(&message).await {
                            tracing::debug!(
                                provider_kind = "docker",
                                sandbox_id = %sandbox_id,
                                error = ?error,
                                "stdio output reader closed"
                            );
                            break;
                        }
                    }
                    Some(Ok(LogOutput::StdErr { message })) => tail.push(&message),
                    Some(Ok(LogOutput::StdIn { .. })) => {}
                }
            }
            if let Err(error) = stdout_writer.shutdown().await {
                tracing::debug!(
                    provider_kind = "docker",
                    sandbox_id = %sandbox_id,
                    error = ?error,
                    "stdio output pipe close failed"
                );
            }
        });

        let handle = DockerStdioHandle {
            exec: Self::new(
                self.docker.clone(),
                self.container_id.clone(),
                self.working_dir.clone(),
                self.base_env.clone(),
            ),
            exec_id: exec.id,
            stop_file,
            stop_requested: AtomicBool::new(false),
        };
        Ok(StdioProcess {
            stdin: Box::pin(input),
            stdout: Box::pin(stdout_reader),
            stderr_tail,
            handle: Box::new(handle),
        })
    }
}

struct DockerStdioHandle {
    exec:           DockerExec,
    exec_id:        String,
    stop_file:      String,
    /// At most one stop request per handle: a repeat call, or one after
    /// the wrapper already consumed the stop file, would spawn a fresh
    /// exec and leave a stray stop file behind.
    stop_requested: AtomicBool,
}

#[async_trait]
impl StdioProcessHandle for DockerStdioHandle {
    #[tracing::instrument(
        skip_all,
        fields(provider_kind = "docker", sandbox_id = %self.exec.container_id)
    )]
    async fn terminate(&self) {
        if self.stop_requested.swap(true, Ordering::SeqCst) {
            return;
        }
        // An already-exited process needs no stop request: the wrapper
        // that would consume the stop file is gone, so the request
        // would spawn a pointless exec and leave a permanent stray file
        // (fabro gated on observed termination the same way). An
        // inspect failure still sends the stop — when in doubt, kill.
        if let Ok(inspect) = self.exec.docker.inspect_exec(&self.exec_id).await {
            if inspect.running != Some(true) {
                return;
            }
        }
        // The trait offers no error channel; awaiting at least keeps
        // the request ordered before any caller-side cleanup.
        if let Err(error) = self.exec.request_stop(&self.stop_file).await {
            tracing::warn!(error = %error, "stdio stop request failed");
        }
    }

    #[tracing::instrument(
        skip_all,
        fields(provider_kind = "docker", sandbox_id = %self.exec.container_id)
    )]
    async fn wait(&self) -> (Termination, Option<i32>) {
        let mut errors_since: Option<Instant> = None;
        let mut retry_delay = Duration::from_millis(100);
        loop {
            match self.exec.docker.inspect_exec(&self.exec_id).await {
                Ok(inspect) if inspect.running == Some(true) => {
                    errors_since = None;
                    retry_delay = Duration::from_millis(100);
                    time::sleep(Duration::from_millis(100)).await;
                }
                Ok(inspect) => {
                    let code = inspect.exit_code.and_then(|code| i32::try_from(code).ok());
                    return (Termination::Exited, code);
                }
                // A transient daemon hiccup must not report an end that
                // was never observed; give up with `Unknown` only after
                // the daemon has been unreachable for the whole bound.
                Err(error) => {
                    if errors_since.is_none() {
                        tracing::warn!("stdio status polling failed");
                    }
                    let since = *errors_since.get_or_insert_with(Instant::now);
                    if since.elapsed() >= WAIT_INSPECT_RETRY {
                        let error = docker_error("polling stdio status", error);
                        tracing::error!(error = %error, "stdio status remained unavailable");
                        return (Termination::Unknown, None);
                    }
                    time::sleep(retry_delay).await;
                    retry_delay = (retry_delay * 2).min(Duration::from_secs(1));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error as _;

    use super::*;

    #[test]
    fn docker_mapping_preserves_sources_and_retry_metadata() {
        let error = docker_error(
            "listing containers",
            DockerApiError::DockerResponseServerError {
                status_code: 503,
                message:     "daemon unavailable".to_owned(),
            },
        );
        let Error::Provider(provider) = error else {
            panic!("expected a provider error");
        };
        assert_eq!(provider.message, "listing containers");
        assert_eq!(provider.code.as_deref(), Some("503"));
        assert!(provider.retryable);
        assert_eq!(
            provider.source().expect("provider source").to_string(),
            "Docker responded with status code 503: daemon unavailable"
        );
    }
}
