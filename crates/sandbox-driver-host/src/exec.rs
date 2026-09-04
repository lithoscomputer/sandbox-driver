use std::collections::BTreeMap;
#[cfg(unix)]
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::pin::pin;
use std::process::Stdio;
use std::sync::OnceLock;
use std::time::{Duration, Instant};
use std::{env, fs, future, io};

use async_trait::async_trait;
#[cfg(unix)]
use nix::sys::signal::Signal;
use sandbox_driver::{
    Error, Exec, ExecControls, ExecResult, ExecSpec, ExecStreamingResult, OutputCaptureBuffer,
    OutputSanitization, OutputSanitizer, OutputSink, OutputStream, Result, SpawnSpec, StderrTail,
    StdinSource, StdioProcess, StdioProcessHandle, Termination,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt, copy};
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

/// The environment a host command starts from: the inherited process env
/// through the fail-closed secret filter, with `base_env` overlaid.
/// [`crate::HostSandbox::environment`] reports exactly this, so a caller
/// reads the same variables a command would see before its own spec env.
pub(crate) fn effective_env(base_env: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    let mut env = BTreeMap::new();
    for (key, value) in env::vars_os() {
        let (Some(key), Some(value)) = (key.to_str(), value.to_str()) else {
            continue;
        };
        if key != BASH_ENV_VAR && !inherited_var_is_sensitive(key) {
            env.insert(key.to_owned(), value.to_owned());
        }
    }
    for (key, value) in base_env {
        if key != BASH_ENV_VAR {
            env.insert(key.clone(), value.clone());
        }
    }
    env
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
    working_dir:                PathBuf,
    base_env:                   BTreeMap<String, String>,
    /// Managed workspaces live under the OS temp directory, which the
    /// OS cleans periodically; recreate rather than failing every exec
    /// forever. Designated directories stay caller-owned and are never
    /// created here.
    recreate_missing_workspace: bool,
    bash_path:                  OnceLock<PathBuf>,
}

impl HostExec {
    pub fn new(
        working_dir: PathBuf,
        base_env: BTreeMap<String, String>,
        recreate_missing_workspace: bool,
    ) -> Self {
        Self {
            working_dir,
            base_env,
            recreate_missing_workspace,
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
        if self.recreate_missing_workspace && !self.working_dir.exists() {
            fs::create_dir_all(&self.working_dir)
                .map_err(|error| Error::io("recreating managed workspace", error))?;
        }
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
    // Windows resolves executables through PATHEXT (`bash.exe`), so the
    // bare name alone would never match a Git Bash install.
    #[cfg(windows)]
    let extensions: Vec<String> = env::var_os("PATHEXT")
        .map(|value| {
            value
                .to_string_lossy()
                .split(';')
                .map(str::to_ascii_lowercase)
                .collect()
        })
        .unwrap_or_else(|| vec![".exe".to_owned(), ".cmd".to_owned(), ".bat".to_owned()]);
    for dir in env::split_paths(&paths) {
        let candidate = dir.join("bash");
        if candidate.is_file() {
            return Some(candidate);
        }
        #[cfg(windows)]
        for extension in &extensions {
            let candidate = dir.join(format!("bash{extension}"));
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    None
}

#[cfg(unix)]
fn signal_process_group(child: &Child, signal: Signal) {
    if let Some(pid) = child.id() {
        use nix::sys::signal::killpg;
        use nix::unistd::Pid;
        // A pid that does not fit i32 must skip the kill entirely: a
        // zero pgid would signal the caller's own process group.
        let Ok(pid) = i32::try_from(pid) else {
            return;
        };
        let _ = killpg(Pid::from_raw(pid), signal);
    }
}

/// Sends SIGTERM to the process group, waits `grace` for a graceful exit,
/// then SIGKILLs the group and the child directly.
///
/// The direct kill is the guarantee: a command that moved itself out of
/// its process group makes the group signals miss entirely (killpg on
/// an empty group is ESRCH), and the callers' subsequent `wait()` would
/// hang forever. SIGKILL to the immediate child always lands, and
/// `kill()` reaps it, so a completed terminate means a returned wait.
async fn terminate_process_group(child: &mut Child, grace: Duration) {
    #[cfg(unix)]
    {
        signal_process_group(child, Signal::SIGTERM);
        if time::timeout(grace, child.wait()).await.is_ok() {
            return;
        }
        signal_process_group(child, Signal::SIGKILL);
        let _ = child.kill().await;
    }
    #[cfg(not(unix))]
    {
        let _ = grace;
        let _ = child.kill().await;
    }
}

/// SIGKILLs the process group and the child directly, with no grace: the
/// [`ExecControls::kill`] path.
async fn kill_process_group(child: &mut Child) {
    #[cfg(unix)]
    signal_process_group(child, Signal::SIGKILL);
    let _ = child.kill().await;
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

async fn write_stdin(mut stdin: ChildStdin, bytes: Vec<u8>) -> Result<()> {
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

/// Copies a streamed source into the process stdin, then closes it for
/// EOF. A command that stops reading disconnecting the pipe is normal;
/// any other failure means the command saw truncated input.
async fn stream_stdin_into(mut stdin: ChildStdin, source: StdinSource) -> Result<()> {
    let Some(mut reader) = source.take() else {
        // Another consumer already took the reader; nothing to write.
        let _ = stdin.shutdown().await;
        return Ok(());
    };
    if let Err(error) = copy(&mut reader, &mut stdin).await {
        if is_disconnect(&error) {
            return Ok(());
        }
        return Err(Error::io("streaming exec stdin", error));
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
    output_sanitization: OutputSanitization,
) -> PumpEnd {
    let mut buffer = [0u8; 8192];
    let mut sanitizer = OutputSanitizer::new(output_sanitization);
    loop {
        match reader.read(&mut buffer).await {
            Ok(0) => {
                let chunk = sanitizer.finish();
                capture.push(&chunk);
                if !chunk.is_empty() {
                    if let Some(sink) = sink {
                        if sink(stream, chunk).await.is_err() {
                            return PumpEnd::SinkError;
                        }
                    }
                }
                return PumpEnd::Eof;
            }
            Err(error) => return PumpEnd::ReadError(error),
            Ok(read) => {
                let chunk = sanitizer.push(&buffer[..read]);
                capture.push(&chunk);
                if !chunk.is_empty() {
                    if let Some(sink) = sink {
                        if sink(stream, chunk).await.is_err() {
                            return PumpEnd::SinkError;
                        }
                    }
                }
            }
        }
    }
}

#[async_trait]
impl Exec for HostExec {
    #[tracing::instrument(skip_all, fields(provider_kind = "host"), err)]
    async fn run(&self, spec: &ExecSpec) -> Result<ExecResult> {
        let streaming = self.run_streaming(spec, ExecControls::default()).await?;
        Ok(streaming.result)
    }

    #[tracing::instrument(
        skip_all,
        fields(provider_kind = "host", has_stdin = spec.stdin.is_some()),
        err
    )]
    #[expect(
        clippy::large_futures,
        reason = "the exec future owns bounded stream and process state for its operation span"
    )]
    async fn run_streaming(
        &self,
        spec: &ExecSpec,
        controls: ExecControls,
    ) -> Result<ExecStreamingResult> {
        let started = Instant::now();
        let grace = controls.grace.unwrap_or(TERM_GRACE);
        let stream_stdin = controls.stdin.clone();
        let wants_stdin = spec.stdin.is_some() || stream_stdin.is_some();
        let mut command = self.command(&spec.command, spec.working_dir.as_deref(), &spec.env)?;
        command.stdin(if wants_stdin {
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
        // write cannot deadlock against a full output pipe. A streamed
        // source is copied for the life of the command; a fixed
        // `spec.stdin` is written once. The two never coexist (the
        // control-plane contract), so a stream wins if both are set.
        let child_stdin = child.stdin.take();
        let stdin_task = match (child_stdin, stream_stdin, spec.stdin.clone()) {
            (Some(stdin), Some(source), _) => Some(tokio::spawn(stream_stdin_into(stdin, source))),
            (Some(stdin), None, Some(bytes)) => Some(tokio::spawn(write_stdin(stdin, bytes))),
            _ => None,
        };

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
        let mut drain_truncated = false;
        let (termination, status) = {
            let mut pumps = pin!(async {
                tokio::join!(
                    pump_stream(
                        stdout,
                        OutputStream::Stdout,
                        &mut stdout_capture,
                        sink,
                        spec.output_sanitization,
                    ),
                    pump_stream(
                        stderr,
                        OutputStream::Stderr,
                        &mut stderr_capture,
                        sink,
                        spec.output_sanitization,
                    ),
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
            let kill = controls.kill.clone();
            let mut killed = pin!(async {
                match &kill {
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
                            terminate_process_group(&mut child, grace).await;
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
                        terminate_process_group(&mut child, grace).await;
                        break (Termination::Cancelled, None);
                    }
                    () = &mut killed => {
                        kill_process_group(&mut child).await;
                        break (Termination::Killed, None);
                    }
                    () = &mut timeout => {
                        terminate_process_group(&mut child, grace).await;
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
                match time::timeout(DRAIN_GRACE, &mut pumps).await {
                    Ok((out_end, err_end)) => {
                        for end in [out_end, err_end] {
                            if let PumpEnd::ReadError(error) = end {
                                read_error.get_or_insert(error);
                            }
                        }
                    }
                    // Unread bytes were abandoned with the pipes: the
                    // capture stats must say the accounting is short.
                    Err(_elapsed) => drain_truncated = true,
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
        #[cfg(unix)]
        let exit_signal = ExitStatusExt::signal(&status);
        #[cfg(not(unix))]
        let exit_signal: Option<i32> = None;

        let (stdout_bytes, mut stdout_stats) = stdout_capture.into_parts();
        let (stderr_bytes, mut stderr_stats) = stderr_capture.into_parts();
        if drain_truncated {
            stdout_stats.truncated = true;
            stderr_stats.truncated = true;
        }
        let mut result = ExecResult::new(termination, exit_code, started.elapsed());
        result.signal = exit_signal;
        result.stdout = stdout_bytes;
        result.stderr = stderr_bytes;

        let mut streaming = ExecStreamingResult::new(result);
        streaming.streams_separated = true;
        streaming.live_streaming = true;
        streaming.stdout_capture = stdout_stats;
        streaming.stderr_capture = stderr_stats;
        Ok(streaming)
    }

    #[tracing::instrument(skip_all, fields(provider_kind = "host"), err)]
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
                    Ok(0) => break,
                    Err(error) => {
                        tracing::warn!(
                            provider_kind = "host",
                            error = ?error,
                            "stdio stderr reader failed"
                        );
                        break;
                    }
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
                    Err(error) => {
                        tracing::error!(
                            provider_kind = "host",
                            error = ?error,
                            "stdio process wait failed"
                        );
                        (Termination::Unknown, None)
                    }
                },
                () = async {
                    // A dropped handle means terminate can never be
                    // requested; keep waiting for the natural exit.
                    if terminate_rx.wait_for(|requested| *requested).await.is_err() {
                        future::pending::<()>().await;
                    }
                } => {
                    terminate_process_group(&mut child, TERM_GRACE).await;
                    let code = match child.wait().await {
                        Ok(status) => status.code(),
                        Err(error) => {
                            tracing::error!(
                                provider_kind = "host",
                                error = ?error,
                                "terminated stdio process wait failed"
                            );
                            None
                        }
                    };
                    (Termination::Cancelled, code)
                }
            };
            if outcome_tx.send(Some(outcome)).is_err() {
                tracing::debug!(provider_kind = "host", "stdio process handle dropped");
            }
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
            Err(error) => {
                tracing::error!(
                    provider_kind = "host",
                    error = ?error,
                    "stdio process supervisor stopped"
                );
                (Termination::Unknown, None)
            }
        }
    }
}

#[async_trait]
impl StdioProcessHandle for HostStdioHandle {
    #[tracing::instrument(skip_all, fields(provider_kind = "host"))]
    async fn terminate(&self) {
        let _ = self.terminate_tx.send(true);
        // Return only after the process is reaped, so callers can clean
        // up (delete the workspace, say) without racing a live process.
        let _ = self.outcome().await;
    }

    #[tracing::instrument(skip_all, fields(provider_kind = "host"))]
    async fn wait(&self) -> (Termination, Option<i32>) {
        self.outcome().await
    }
}
