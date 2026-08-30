use std::collections::BTreeMap;
use std::result::Result as StdResult;
use std::sync::atomic::{AtomicU64, Ordering};
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
    OutputSink, OutputStream, ProviderError, ProviderKind, Result, SpawnSpec, StderrTail,
    StdioProcess, StdioProcessHandle, Termination,
};
use tokio::io::{AsyncWriteExt, duplex};
use tokio::time;

/// The container-side interpreter the Bash contract requires.
const CONTAINER_BASH: &str = "/bin/bash";
const BASH_ENV_VAR: &str = "BASH_ENV";
/// Grace period for draining output after a stop request. Must exceed
/// the watcher's poll interval plus [`TERM_GRACE_SECONDS`].
const KILL_DRAIN_GRACE: Duration = Duration::from_secs(10);
/// The in-container watcher's poll interval for the stop file.
const STOP_POLL_SLEEP_SECONDS: &str = "0.1";
/// Grace between the watcher's SIGTERM and SIGKILL so processes can run
/// traps, flush output, and release locks. The wrapper's `wait` returns
/// as soon as the process exits, so a generous grace costs nothing on
/// the normal path.
const TERM_GRACE_SECONDS: &str = "2";

pub(crate) fn docker_error(context: &str, error: &DockerApiError) -> Error {
    let kind = ProviderKind::try_new("docker").expect("static kind is valid");
    let mut provider = ProviderError::new(kind, format!("{context}: {error}"));
    if let DockerApiError::DockerResponseServerError { status_code, .. } = error {
        provider.code = Some(status_code.to_string());
    }
    Error::Provider(provider)
}

pub(crate) fn is_not_found(error: &DockerApiError) -> bool {
    matches!(error, DockerApiError::DockerResponseServerError {
        status_code: 404,
        ..
    })
}

fn is_not_modified(error: &DockerApiError) -> bool {
    matches!(error, DockerApiError::DockerResponseServerError {
        status_code: 304,
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
        Err(error) => Err(docker_error(context, &error)),
    }
}

fn shell_quote(value: &str) -> String {
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
    fn wrapped(user_command: &str, stop_file: &str, pid_file: &str, forward_stdin: bool) -> String {
        let quoted_cmd = shell_quote(user_command);
        let stop_file = shell_quote(stop_file);
        let pid_file = shell_quote(pid_file);
        let (save_stdin, stdin_redirect, close_stdin) = if forward_stdin {
            ("exec 3<&0\n", "<&3", "exec 3<&-\n")
        } else {
            ("", "< /dev/null", "")
        };
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
               rm -f \"$stop_file\"\n\
               exit 143\n\
             fi\n\
             (\n\
               while [ ! -e \"$stop_file\" ]; do sleep {STOP_POLL_SLEEP_SECONDS}; done\n\
               while [ ! -s \"$pid_file\" ]; do sleep {STOP_POLL_SLEEP_SECONDS}; done\n\
               child=$(cat \"$pid_file\")\n\
               kill -TERM \"-$child\" 2>/dev/null || kill -TERM \"$child\" 2>/dev/null || true\n\
               sleep {TERM_GRACE_SECONDS}\n\
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

    /// Requests a stop, best-effort and detached. Creating the stop
    /// file triggers the in-container watcher; a stop that arrives
    /// before the command starts is honored by the wrapper's pre-check.
    fn spawn_stop(&self, stop_file: String) {
        let docker = self.docker.clone();
        let container_id = self.container_id.clone();
        tokio::spawn(async move {
            let command = format!(
                "mkdir -p /tmp/.sandbox-driver && : > {}",
                shell_quote(&stop_file)
            );
            let options = CreateExecOptions {
                cmd: Some(vec![CONTAINER_BASH.to_owned(), "-c".to_owned(), command]),
                attach_stdout: Some(false),
                attach_stderr: Some(false),
                ..Default::default()
            };
            if let Ok(exec) = docker.create_exec(&container_id, options).await {
                let _ = docker.start_exec(&exec.id, None::<StartExecOptions>).await;
            }
        });
    }

    async fn exit_code(&self, exec_id: &str) -> Result<Option<i32>> {
        let inspect = self
            .docker
            .inspect_exec(exec_id)
            .await
            .map_err(|error| docker_error("inspecting exec", &error))?;
        Ok(inspect.exit_code.and_then(|code| i32::try_from(code).ok()))
    }
}

#[async_trait]
impl Exec for DockerExec {
    async fn run(&self, spec: &ExecSpec) -> Result<ExecResult> {
        let streaming = self.run_streaming(spec, ExecControls::default()).await?;
        Ok(streaming.result)
    }

    async fn run_streaming(
        &self,
        spec: &ExecSpec,
        controls: ExecControls,
    ) -> Result<ExecStreamingResult> {
        let started = Instant::now();
        let (stop_file, pid_file) = self.control_paths();
        let has_stdin = spec.stdin.is_some();
        let wrapper = Self::wrapped(&spec.command, &stop_file, &pid_file, has_stdin);

        let working_dir = spec
            .working_dir
            .clone()
            .unwrap_or_else(|| self.working_dir.clone());
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
            .map_err(|error| docker_error("creating exec", &error))?;
        let start = self
            .docker
            .start_exec(&exec.id, None::<StartExecOptions>)
            .await
            .map_err(|error| docker_error("starting exec", &error))?;
        let StartExecResults::Attached {
            mut output,
            mut input,
        } = start
        else {
            return Err(docker_error("starting exec", &DockerApiError::IOError {
                err: io::Error::other("exec started detached"),
            }));
        };

        if let Some(bytes) = spec.stdin.clone() {
            tokio::spawn(async move {
                let _ = input.write_all(&bytes).await;
                let _ = input.shutdown().await;
            });
        } else {
            drop(input);
        }

        let mut stdout_capture = OutputCaptureBuffer::new(controls.retained_output_limit);
        let mut stderr_capture = OutputCaptureBuffer::new(controls.retained_output_limit);
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
                        stdout_capture.push(&message);
                        if let Some(sink) = sink {
                            if sink(OutputStream::Stdout, message.to_vec()).await.is_err()
                                && !kill_fired
                            {
                                termination = Termination::Cancelled;
                                kill_fired = true;
                                drain_deadline = Some(Instant::now() + KILL_DRAIN_GRACE);
                                self.spawn_stop(stop_file.clone());
                            }
                        }
                    }
                    Some(Ok(LogOutput::StdErr { message })) => {
                        stderr_capture.push(&message);
                        if let Some(sink) = sink {
                            if sink(OutputStream::Stderr, message.to_vec()).await.is_err()
                                && !kill_fired
                            {
                                termination = Termination::Cancelled;
                                kill_fired = true;
                                drain_deadline = Some(Instant::now() + KILL_DRAIN_GRACE);
                                self.spawn_stop(stop_file.clone());
                            }
                        }
                    }
                    Some(Ok(_)) => {}
                },
                () = cancelled => {
                    termination = Termination::Cancelled;
                    kill_fired = true;
                    drain_deadline = Some(Instant::now() + KILL_DRAIN_GRACE);
                    self.spawn_stop(stop_file.clone());
                }
                () = timeout => {
                    termination = Termination::TimedOut;
                    kill_fired = true;
                    drain_deadline = Some(Instant::now() + KILL_DRAIN_GRACE);
                    self.spawn_stop(stop_file.clone());
                }
                () = drain_timeout => break,
            }
        }

        if let Some(error) = stream_error {
            return Err(docker_error("reading exec output", &error));
        }
        let exit_code = self.exit_code(&exec.id).await?;
        let (stdout_bytes, stdout_stats) = stdout_capture.into_parts();
        let (stderr_bytes, stderr_stats) = stderr_capture.into_parts();
        let mut result = ExecResult::new(termination, exit_code, started.elapsed());
        result.stdout = stdout_bytes;
        result.stderr = stderr_bytes;
        let mut streaming = ExecStreamingResult::new(result);
        streaming.streams_separated = true;
        streaming.live_streaming = true;
        streaming.stdout_capture = stdout_stats;
        streaming.stderr_capture = stderr_stats;
        Ok(streaming)
    }

    async fn spawn_stdio(&self, spec: &SpawnSpec) -> Result<StdioProcess> {
        let (stop_file, pid_file) = self.control_paths();
        let wrapper = Self::wrapped(&spec.command, &stop_file, &pid_file, true);
        let working_dir = spec
            .working_dir
            .clone()
            .unwrap_or_else(|| self.working_dir.clone());
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
            .map_err(|error| docker_error("creating stdio exec", &error))?;
        let start = self
            .docker
            .start_exec(&exec.id, None::<StartExecOptions>)
            .await
            .map_err(|error| docker_error("starting stdio exec", &error))?;
        let StartExecResults::Attached { mut output, input } = start else {
            return Err(docker_error(
                "starting stdio exec",
                &DockerApiError::IOError {
                    err: io::Error::other("exec started detached"),
                },
            ));
        };

        // Demux the attached stream into a stdout pipe and a stderr tail.
        let (stdout_writer, stdout_reader) = duplex(64 * 1024);
        let stderr_tail = StderrTail::default();
        let tail = stderr_tail.clone();
        tokio::spawn(async move {
            let mut stdout_writer = stdout_writer;
            loop {
                match output.next().await {
                    None => break,
                    // Make a transport failure visible in the diagnostic
                    // tail instead of ending the stream silently.
                    Some(Err(error)) => {
                        tail.push(
                            format!("sandbox-driver: stdio output stream error: {error}\n")
                                .as_bytes(),
                        );
                        break;
                    }
                    Some(Ok(LogOutput::StdOut { message } | LogOutput::Console { message })) => {
                        if stdout_writer.write_all(&message).await.is_err() {
                            break;
                        }
                    }
                    Some(Ok(LogOutput::StdErr { message })) => tail.push(&message),
                    Some(Ok(LogOutput::StdIn { .. })) => {}
                }
            }
            let _ = stdout_writer.shutdown().await;
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
    exec:      DockerExec,
    exec_id:   String,
    stop_file: String,
}

#[async_trait]
impl StdioProcessHandle for DockerStdioHandle {
    async fn terminate(&self) {
        self.exec.spawn_stop(self.stop_file.clone());
    }

    async fn wait(&self) -> (Termination, Option<i32>) {
        loop {
            match self.exec.docker.inspect_exec(&self.exec_id).await {
                Ok(inspect) if inspect.running == Some(true) => {
                    time::sleep(Duration::from_millis(100)).await;
                }
                Ok(inspect) => {
                    let code = inspect.exit_code.and_then(|code| i32::try_from(code).ok());
                    return (Termination::Exited, code);
                }
                Err(_) => return (Termination::Unknown, None),
            }
        }
    }
}
