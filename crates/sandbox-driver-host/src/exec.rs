use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::pin::pin;
use std::process::Stdio;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use std::{future, mem};

use async_trait::async_trait;
#[cfg(unix)]
use nix::sys::signal::Signal;
use sandbox_driver::{
    Error, Exec, ExecControls, ExecResult, ExecSpec, ExecStreamingResult, OutputCaptureBuffer,
    OutputSink, OutputStream, Result, SpawnSpec, StderrTail, StdioProcess, StdioProcessHandle,
    Termination,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::process::{Child, Command};
use tokio::time;

/// The variable the Bash contract requires stripping before every run.
const BASH_ENV_VAR: &str = "BASH_ENV";

/// Bound on draining remaining output after the process has ended, so a
/// backgrounded grandchild holding the pipes cannot stall the call.
const DRAIN_GRACE: Duration = Duration::from_secs(10);

/// Grace between SIGTERM and SIGKILL so processes can run traps, flush
/// output, and release locks (a killed `git` leaves `.git/index.lock`
/// behind otherwise).
const TERM_GRACE: Duration = Duration::from_secs(2);

/// Command execution on the local machine.
///
/// Implements the Bash contract: every command runs as `bash -c <command>`
/// with `bash` resolved through the caller's `PATH` (NixOS has no
/// `/bin/bash`), no login mode, no option changes, and `BASH_ENV` removed.
/// Processes run in their own process group so cancellation and timeouts
/// kill the whole tree.
pub struct HostExec {
    working_dir: PathBuf,
    base_env:    BTreeMap<String, String>,
}

impl HostExec {
    pub fn new(working_dir: PathBuf, base_env: BTreeMap<String, String>) -> Self {
        Self {
            working_dir,
            base_env,
        }
    }

    fn resolve_dir(&self, dir: Option<&str>) -> PathBuf {
        match dir {
            None => self.working_dir.clone(),
            Some(dir) => {
                let path = Path::new(dir);
                if path.is_absolute() {
                    path.to_path_buf()
                } else {
                    self.working_dir.join(path)
                }
            }
        }
    }

    fn command(
        &self,
        program: &str,
        working_dir: Option<&str>,
        env: &BTreeMap<String, String>,
    ) -> Command {
        let mut command = Command::new("bash");
        command.arg("-c").arg(program);
        command.current_dir(self.resolve_dir(working_dir));
        command.env_remove(BASH_ENV_VAR);
        for (key, value) in &self.base_env {
            command.env(key, value);
        }
        for (key, value) in env {
            command.env(key, value);
        }
        #[cfg(unix)]
        command.process_group(0);
        command.kill_on_drop(true);
        command
    }
}

#[cfg(unix)]
fn signal_process_group(child: &Child, signal: Signal) {
    if let Some(pid) = child.id() {
        use nix::sys::signal::killpg;
        use nix::unistd::Pid;
        let pgid = Pid::from_raw(i32::try_from(pid).unwrap_or_default());
        let _ = killpg(pgid, signal);
    }
}

fn kill_process_group(child: &Child) {
    #[cfg(unix)]
    signal_process_group(child, Signal::SIGKILL);
    #[cfg(not(unix))]
    let _ = child;
}

/// Sends SIGTERM to the process group, waits [`TERM_GRACE`] for a
/// graceful exit, then SIGKILLs the group.
async fn terminate_process_group(child: &mut Child) {
    #[cfg(unix)]
    {
        signal_process_group(child, Signal::SIGTERM);
        if time::timeout(TERM_GRACE, child.wait()).await.is_err() {
            signal_process_group(child, Signal::SIGKILL);
        }
    }
    #[cfg(not(unix))]
    {
        let _ = child.kill().await;
    }
}

enum PumpEnd {
    Eof,
    SinkError,
}

/// Reads one output stream to EOF, feeding the capture buffer and sink.
async fn pump_stream(
    mut reader: impl AsyncRead + Unpin,
    stream: OutputStream,
    capture: &mut OutputCaptureBuffer,
    sink: Option<&OutputSink>,
) -> PumpEnd {
    let mut buffer = [0u8; 8192];
    loop {
        match reader.read(&mut buffer).await {
            Ok(0) | Err(_) => return PumpEnd::Eof,
            Ok(read) => {
                let chunk = &buffer[..read];
                capture.push(chunk);
                if let Some(sink) = sink {
                    if sink(stream, chunk.to_vec()).await.is_err() {
                        return PumpEnd::SinkError;
                    }
                }
            }
        }
    }
}

#[async_trait]
impl Exec for HostExec {
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
        let mut command = self.command(&spec.command, spec.working_dir.as_deref(), &spec.env);
        command.stdin(if spec.stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        });
        command.stdout(Stdio::piped());
        command.stderr(Stdio::piped());

        let mut child = command
            .spawn()
            .map_err(|error| Error::io("spawning bash for exec", error))?;

        if let Some(bytes) = spec.stdin.clone() {
            if let Some(mut stdin) = child.stdin.take() {
                // Write-then-EOF, concurrently with output pumping so a
                // large write cannot deadlock against a full output pipe.
                // A broken pipe (`head -1`) is normal.
                tokio::spawn(async move {
                    let _ = stdin.write_all(&bytes).await;
                    let _ = stdin.shutdown().await;
                });
            }
        }

        let stdout = child.stdout.take().expect("stdout was piped");
        let stderr = child.stderr.take().expect("stderr was piped");
        let mut stdout_capture = OutputCaptureBuffer::new(controls.retained_output_limit);
        let mut stderr_capture = OutputCaptureBuffer::new(controls.retained_output_limit);
        let sink = controls.sink.as_ref();

        // The process, the cancel token, and the timeout race until the
        // process ends; the pumps run alongside without gating any of
        // them, so a command that closes its own stdout/stderr (a
        // daemonizing child) is still bounded by the timeout. Remaining
        // output is drained after the process ends, bounded by
        // `DRAIN_GRACE`.
        let (termination, status) = {
            let mut pumps = pin!(async {
                tokio::join!(
                    pump_stream(stdout, OutputStream::Stdout, &mut stdout_capture, sink),
                    pump_stream(stderr, OutputStream::Stderr, &mut stderr_capture, sink),
                )
            });
            let mut pumps_done = false;

            let cancel = controls.cancel.clone();
            let mut cancelled = pin!(async {
                match &cancel {
                    Some(token) => token.cancelled().await,
                    None => future::pending().await,
                }
            });
            let mut timeout = pin!(async {
                match spec.timeout {
                    Some(timeout) => time::sleep(timeout).await,
                    None => future::pending().await,
                }
            });

            let (termination, status) = loop {
                tokio::select! {
                    (out_end, err_end) = &mut pumps, if !pumps_done => {
                        pumps_done = true;
                        if matches!(out_end, PumpEnd::SinkError)
                            || matches!(err_end, PumpEnd::SinkError)
                        {
                            terminate_process_group(&mut child).await;
                            break (Termination::Cancelled, None);
                        }
                    }
                    wait_result = child.wait() => {
                        let status = wait_result.map_err(|error| {
                            Error::io("waiting for exec process", error)
                        })?;
                        break (Termination::Exited, Some(status));
                    }
                    () = &mut cancelled => {
                        terminate_process_group(&mut child).await;
                        break (Termination::Cancelled, None);
                    }
                    () = &mut timeout => {
                        terminate_process_group(&mut child).await;
                        break (Termination::TimedOut, None);
                    }
                }
            };

            let status = match status {
                Some(status) => status,
                None => child
                    .wait()
                    .await
                    .map_err(|error| Error::io("waiting for exec process", error))?,
            };
            if !pumps_done {
                let _ = time::timeout(DRAIN_GRACE, &mut pumps).await;
            }
            (termination, status)
        };
        let exit_code = status.code();

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
        let program = format!("exec {}", spec.command);
        let mut command = self.command(&program, spec.working_dir.as_deref(), &spec.env);
        command.stdin(Stdio::piped());
        command.stdout(Stdio::piped());
        command.stderr(Stdio::piped());

        let mut child = command
            .spawn()
            .map_err(|error| Error::io("spawning bash for stdio process", error))?;
        let stdin = child.stdin.take().expect("stdin was piped");
        let stdout = child.stdout.take().expect("stdout was piped");
        let stderr = child.stderr.take().expect("stderr was piped");

        let stderr_tail = StderrTail::default();
        let tail = stderr_tail.clone();
        // Ends at stderr EOF, i.e. when the process exits.
        tokio::spawn(async move {
            let mut reader = stderr;
            let mut buffer = [0u8; 4096];
            loop {
                match reader.read(&mut buffer).await {
                    Ok(0) | Err(_) => break,
                    Ok(read) => tail.push(&buffer[..read]),
                }
            }
        });

        Ok(StdioProcess {
            stdin: Box::pin(stdin),
            stdout: Box::pin(stdout),
            stderr_tail,
            handle: Box::new(HostStdioHandle {
                state: Mutex::new(StdioState::Running(child)),
            }),
        })
    }
}

enum StdioState {
    Running(Child),
    Finished(Termination, Option<i32>),
    Waiting,
}

struct HostStdioHandle {
    state: Mutex<StdioState>,
}

impl HostStdioHandle {
    fn take_child(&self) -> Option<Child> {
        let mut state = self.state.lock().expect("stdio state lock");
        match mem::replace(&mut *state, StdioState::Waiting) {
            StdioState::Running(child) => Some(child),
            other => {
                *state = other;
                None
            }
        }
    }
}

#[async_trait]
impl StdioProcessHandle for HostStdioHandle {
    async fn terminate(&self) {
        let state = self.state.lock().expect("stdio state lock");
        if let StdioState::Running(child) = &*state {
            kill_process_group(child);
        }
    }

    async fn wait(&self) -> (Termination, Option<i32>) {
        if let Some(mut child) = self.take_child() {
            let outcome = child.wait().await;
            let (termination, code) = match outcome {
                Ok(status) => (Termination::Exited, status.code()),
                Err(_) => (Termination::Unknown, None),
            };
            *self.state.lock().expect("stdio state lock") = StdioState::Finished(termination, code);
            return (termination, code);
        }
        // Another waiter owns the child or it already finished; poll the
        // recorded outcome.
        loop {
            {
                let state = self.state.lock().expect("stdio state lock");
                if let StdioState::Finished(termination, code) = &*state {
                    return (*termination, *code);
                }
            }
            time::sleep(Duration::from_millis(20)).await;
        }
    }
}
