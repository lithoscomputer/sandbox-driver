use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::pin::pin;
use std::process::Stdio;
use std::sync::OnceLock;
use std::time::{Duration, Instant};
use std::{env, future, io};

use async_trait::async_trait;
#[cfg(unix)]
use nix::sys::signal::Signal;
use sandbox_driver::{
    Error, Exec, ExecControls, ExecResult, ExecSpec, ExecStreamingResult, OutputCaptureBuffer,
    OutputSink, OutputStream, Result, SpawnSpec, StderrTail, StdioProcess, StdioProcessHandle,
    Termination,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::process::{Child, ChildStdin, Command};
use tokio::sync::watch;
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

/// Inherited variables always kept, even when their name matches a
/// secret suffix.
const ENV_SAFELIST: &[&str] = &[
    "PATH",
    "HOME",
    "USER",
    "SHELL",
    "LANG",
    "TERM",
    "TMPDIR",
    "GOPATH",
    "CARGO_HOME",
    "NVM_DIR",
];

/// Fail-closed filter for inherited environment variables: anything whose
/// name looks like a secret never reaches a sandboxed command. Explicit
/// spec env is the deliberate channel for secrets and is not filtered.
fn inherited_var_is_sensitive(key: &str) -> bool {
    if ENV_SAFELIST.contains(&key) {
        return false;
    }
    let lower = key.to_lowercase();
    lower.ends_with("_api_key")
        || lower.ends_with("_secret")
        || lower.ends_with("_token")
        || lower.ends_with("_password")
        || lower.ends_with("_credential")
}

/// Command execution on the local machine.
///
/// Implements the Bash contract: every command runs as `bash -c <command>`
/// with `bash` resolved through the caller's `PATH` (NixOS has no
/// `/bin/bash`), no login mode, no option changes, and `BASH_ENV` removed
/// — including from spec-provided env. The parent environment is cleared
/// and rebuilt through a fail-closed secret filter, so ambient worker
/// credentials never reach sandboxed commands. Processes run in their own
/// process group so cancellation and timeouts kill the whole tree.
pub struct HostExec {
    working_dir: PathBuf,
    base_env:    BTreeMap<String, String>,
    bash_path:   OnceLock<PathBuf>,
}

impl HostExec {
    pub fn new(working_dir: PathBuf, base_env: BTreeMap<String, String>) -> Self {
        Self {
            working_dir,
            base_env,
            bash_path: OnceLock::new(),
        }
    }

    /// Resolves, then remembers, the Bash this sandbox runs commands
    /// with. Every spawn goes through here so a spec-provided `PATH`
    /// cannot make spawning fail and a single sandbox can never split
    /// across two interpreters.
    fn bash(&self) -> Result<PathBuf> {
        if let Some(path) = self.bash_path.get() {
            return Ok(path.clone());
        }
        let resolved = resolve_bash_on_path().ok_or_else(|| {
            Error::io(
                "resolving bash",
                io::Error::new(io::ErrorKind::NotFound, "no `bash` on PATH"),
            )
        })?;
        Ok(self.bash_path.get_or_init(|| resolved).clone())
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
    ) -> Result<Command> {
        let mut command = Command::new(self.bash()?);
        command.arg("-c").arg(program);
        command.current_dir(self.resolve_dir(working_dir));
        command.env_clear();
        for (key, value) in env::vars_os() {
            // Keys that are not UTF-8 cannot be checked, so fail closed.
            let Some(key_str) = key.to_str() else {
                continue;
            };
            if key_str != BASH_ENV_VAR && !inherited_var_is_sensitive(key_str) {
                command.env(&key, &value);
            }
        }
        for (key, value) in self.base_env.iter().chain(env) {
            if key != BASH_ENV_VAR {
                command.env(key, value);
            }
        }
        #[cfg(unix)]
        command.process_group(0);
        command.kill_on_drop(true);
        Ok(command)
    }
}

fn resolve_bash_on_path() -> Option<PathBuf> {
    let paths = env::var_os("PATH")?;
    env::split_paths(&paths)
        .map(|dir| dir.join("bash"))
        .find(|candidate| candidate.is_file())
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

/// Writes stdin then closes it for EOF. A command that stops reading its
/// input (`head -1`) disconnecting the pipe is normal; any other failure
/// means the command saw truncated input and must not pass silently.
async fn write_stdin(mut stdin: ChildStdin, bytes: Vec<u8>) -> Result<()> {
    fn is_disconnect(error: &io::Error) -> bool {
        matches!(
            error.kind(),
            io::ErrorKind::BrokenPipe
                | io::ErrorKind::ConnectionReset
                | io::ErrorKind::ConnectionAborted
        )
    }
    if let Err(error) = stdin.write_all(&bytes).await {
        if is_disconnect(&error) {
            return Ok(());
        }
        return Err(Error::io("writing exec stdin", error));
    }
    if let Err(error) = stdin.shutdown().await {
        if is_disconnect(&error) {
            return Ok(());
        }
        return Err(Error::io("closing exec stdin", error));
    }
    Ok(())
}

enum PumpEnd {
    Eof,
    SinkError,
    /// A transport failure mid-stream: output is incomplete, which must
    /// surface as an error, never as a clean exit with truncated output.
    ReadError(io::Error),
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
            Ok(0) => return PumpEnd::Eof,
            Err(error) => return PumpEnd::ReadError(error),
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
        let mut command = self.command(&spec.command, spec.working_dir.as_deref(), &spec.env)?;
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

        // Write-then-EOF, concurrently with output pumping so a large
        // write cannot deadlock against a full output pipe.
        let stdin_task = spec
            .stdin
            .clone()
            .and_then(|bytes| child.stdin.take().map(|stdin| (stdin, bytes)))
            .map(|(stdin, bytes)| tokio::spawn(write_stdin(stdin, bytes)));

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
        let mut read_error: Option<io::Error> = None;
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
                        let sink_error = matches!(out_end, PumpEnd::SinkError)
                            || matches!(err_end, PumpEnd::SinkError);
                        for end in [out_end, err_end] {
                            if let PumpEnd::ReadError(error) = end {
                                read_error.get_or_insert(error);
                            }
                        }
                        if sink_error || read_error.is_some() {
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
                if let Ok((out_end, err_end)) = time::timeout(DRAIN_GRACE, &mut pumps).await {
                    for end in [out_end, err_end] {
                        if let PumpEnd::ReadError(error) = end {
                            read_error.get_or_insert(error);
                        }
                    }
                }
            }
            (termination, status)
        };
        if let Some(stdin_task) = stdin_task {
            // The process is gone, so unwritten stdin bytes are unwanted.
            // Abort instead of joining unbounded: a backgrounded
            // grandchild that inherited the pipe could otherwise block
            // the writer forever.
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
        if let Some(error) = read_error {
            return Err(Error::io("reading exec output", error));
        }
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
        let mut command = self.command(&program, spec.working_dir.as_deref(), &spec.env)?;
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
            handle: Box::new(HostStdioHandle::supervise(child)),
        })
    }
}

type StdioOutcome = (Termination, Option<i32>);

/// Owns the child through a supervisor task so `terminate` works at any
/// time — including while another task is blocked in `wait`.
struct HostStdioHandle {
    terminate_tx: watch::Sender<bool>,
    outcome_rx:   watch::Receiver<Option<StdioOutcome>>,
}

impl HostStdioHandle {
    fn supervise(mut child: Child) -> Self {
        let (terminate_tx, mut terminate_rx) = watch::channel(false);
        let (outcome_tx, outcome_rx) = watch::channel(None);
        tokio::spawn(async move {
            let outcome = tokio::select! {
                status = child.wait() => match status {
                    Ok(status) => (Termination::Exited, status.code()),
                    Err(_) => (Termination::Unknown, None),
                },
                () = async {
                    // A dropped handle means terminate can never be
                    // requested; keep waiting for the natural exit.
                    if terminate_rx.wait_for(|requested| *requested).await.is_err() {
                        future::pending::<()>().await;
                    }
                } => {
                    terminate_process_group(&mut child).await;
                    let code = child.wait().await.ok().and_then(|status| status.code());
                    (Termination::Cancelled, code)
                }
            };
            let _ = outcome_tx.send(Some(outcome));
        });
        Self {
            terminate_tx,
            outcome_rx,
        }
    }

    async fn outcome(&self) -> StdioOutcome {
        let mut outcome_rx = self.outcome_rx.clone();
        match outcome_rx.wait_for(Option::is_some).await {
            Ok(outcome) => (*outcome).expect("guarded by wait_for"),
            Err(_) => (Termination::Unknown, None),
        }
    }
}

#[async_trait]
impl StdioProcessHandle for HostStdioHandle {
    async fn terminate(&self) {
        let _ = self.terminate_tx.send(true);
        // Return only after the process is reaped, so callers can clean
        // up (delete the workspace, say) without racing a live process.
        let _ = self.outcome().await;
    }

    async fn wait(&self) -> (Termination, Option<i32>) {
        self.outcome().await
    }
}
