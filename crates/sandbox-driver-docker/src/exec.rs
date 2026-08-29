use std::collections::BTreeMap;
use std::result::Result as StdResult;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
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
/// Grace period for draining output after a kill.
const KILL_DRAIN_GRACE: Duration = Duration::from_secs(10);

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
/// wrapper that puts it in its own session and records the process-group
/// id in a pid file; timeout and cancellation kill the group through a
/// second exec. The wrapper's `wait` forwards the child's exit code.
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

    fn pidfile(&self) -> String {
        let count = self.exec_counter.fetch_add(1, Ordering::Relaxed);
        format!("/tmp/.sandbox-driver/exec-{}-{count}.pid", process::id())
    }

    /// Wraps a user command so its process group is recorded and killable.
    fn wrapped(user_command: &str, pidfile: &str, forward_stdin: bool) -> String {
        let quoted_cmd = shell_quote(user_command);
        let quoted_pidfile = shell_quote(pidfile);
        if forward_stdin {
            format!(
                "mkdir -p /tmp/.sandbox-driver\n\
                 exec 3<&0\n\
                 setsid {CONTAINER_BASH} -c {quoted_cmd} <&3 &\n\
                 SD_PID=$!\n\
                 exec 3<&-\n\
                 printf '%s' \"$SD_PID\" > {quoted_pidfile}\n\
                 wait \"$SD_PID\""
            )
        } else {
            format!(
                "mkdir -p /tmp/.sandbox-driver\n\
                 setsid {CONTAINER_BASH} -c {quoted_cmd} < /dev/null &\n\
                 SD_PID=$!\n\
                 printf '%s' \"$SD_PID\" > {quoted_pidfile}\n\
                 wait \"$SD_PID\""
            )
        }
    }

    /// Kills the recorded process group, best-effort and detached.
    fn spawn_kill(&self, pidfile: String) {
        let docker = self.docker.clone();
        let container_id = self.container_id.clone();
        tokio::spawn(async move {
            let command = format!(
                "if [ -f {pf} ]; then kill -KILL -\"$(cat {pf})\" 2>/dev/null; fi",
                pf = shell_quote(&pidfile)
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

    async fn exit_code(&self, exec_id: &str) -> Option<i32> {
        let inspect = self.docker.inspect_exec(exec_id).await.ok()?;
        inspect.exit_code.and_then(|code| i32::try_from(code).ok())
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
        let pidfile = self.pidfile();
        let has_stdin = spec.stdin.is_some();
        let wrapper = Self::wrapped(&spec.command, &pidfile, has_stdin);

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
                    None | Some(Err(_)) => break,
                    Some(Ok(LogOutput::StdOut { message } | LogOutput::Console { message })) => {
                        stdout_capture.push(&message);
                        if let Some(sink) = sink {
                            if sink(OutputStream::Stdout, message.to_vec()).await.is_err()
                                && !kill_fired
                            {
                                termination = Termination::Cancelled;
                                kill_fired = true;
                                drain_deadline = Some(Instant::now() + KILL_DRAIN_GRACE);
                                self.spawn_kill(pidfile.clone());
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
                                self.spawn_kill(pidfile.clone());
                            }
                        }
                    }
                    Some(Ok(_)) => {}
                },
                () = cancelled => {
                    termination = Termination::Cancelled;
                    kill_fired = true;
                    drain_deadline = Some(Instant::now() + KILL_DRAIN_GRACE);
                    self.spawn_kill(pidfile.clone());
                }
                () = timeout => {
                    termination = Termination::TimedOut;
                    kill_fired = true;
                    drain_deadline = Some(Instant::now() + KILL_DRAIN_GRACE);
                    self.spawn_kill(pidfile.clone());
                }
                () = drain_timeout => break,
            }
        }

        let exit_code = self.exit_code(&exec.id).await;
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
        let pidfile = self.pidfile();
        let wrapper = Self::wrapped(&spec.command, &pidfile, true);
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
            while let Some(Ok(chunk)) = output.next().await {
                match chunk {
                    LogOutput::StdOut { message } | LogOutput::Console { message } => {
                        if stdout_writer.write_all(&message).await.is_err() {
                            break;
                        }
                    }
                    LogOutput::StdErr { message } => tail.push(&message),
                    LogOutput::StdIn { .. } => {}
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
            pidfile,
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
    exec:    DockerExec,
    exec_id: String,
    pidfile: String,
}

#[async_trait]
impl StdioProcessHandle for DockerStdioHandle {
    async fn terminate(&self) {
        self.exec.spawn_kill(self.pidfile.clone());
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
