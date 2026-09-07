use std::collections::BTreeMap;
#[cfg(unix)]
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::pin::pin;
use std::process::Stdio;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use std::{env, future, io};

use async_trait::async_trait;
#[cfg(unix)]
use nix::sys::signal::Signal;
use sandbox_driver::{
    Error, Exec, ExecControls, ExecResult, ExecSpec, ExecStreamingResult, OutputCaptureBuffer,
    OutputSanitization, OutputSanitizer, OutputSink, OutputStream, Result, SpawnSpec, StderrTail,
    StdioProcess, StdioProcessHandle, Termination, feed_stdin, stop_signal,
};
use tokio::io::{AsyncRead, AsyncReadExt};
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
use tokio::process::Child as HostChild;
use tokio::process::Command;
use tokio::sync::watch;
use tokio::{fs, time};

#[cfg(any(target_os = "linux", target_os = "macos"))]
use crate::fence::{HostChild, ProcessGroups};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use crate::registry;

/// Bash sources this file at startup. Dropped from the inherited
/// environment so a worker's startup file never runs inside a sandboxed
/// `bash -c`; [`sandbox_driver::ExecSpec::bash`] blanks it per command.
const BASH_ENV_VAR: &str = "BASH_ENV";

/// How long the output pipes may stay silent after the process has ended
/// before the drain gives up, so a backgrounded grandchild holding the
/// pipes without writing cannot stall the call. Output that keeps arriving
/// resets the bound: a slow consumer is backpressure, never a reason to
/// drop what the command wrote.
const DRAIN_GRACE: Duration = Duration::from_secs(10);

/// Grace between SIGTERM and SIGKILL when a stdio process is terminated
/// through its handle, so it can run traps, flush output, and release
/// locks (a killed `git` leaves `.git/index.lock` behind otherwise). The
/// exec path has no ladder of its own: its caller escalates.
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
/// Spawns the spec's program and arguments directly; the program is
/// resolved through the command's own `PATH` (the effective environment
/// below, overlaid with the spec env), so a spec that sets `PATH` also
/// chooses where its program comes from. The parent environment is
/// cleared and rebuilt through a fail-closed secret filter, so ambient
/// worker credentials never reach sandboxed commands. Processes run in
/// their own process group so cancellation and timeouts kill the whole
/// tree. On Linux and macOS, a sandbox-owned sentinel keeps the group id
/// pinned until stop, including after the workload exits.
/// Standalone executors release their groups on drop after any spawned stdio
/// process ends. Process-record removal is best effort while Tokio is
/// available.
pub struct HostExec {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    groups:                     Arc<ProcessGroups>,
    working_dir:                PathBuf,
    base_env:                   BTreeMap<String, String>,
    /// Managed workspaces live under the OS temp directory, which the
    /// OS cleans periodically; recreate rather than failing every exec
    /// forever. Designated directories stay caller-owned and are never
    /// created here.
    recreate_missing_workspace: bool,
    /// Silence on the output pipes after exit that ends the drain.
    drain_grace:                Duration,
}

impl HostExec {
    pub fn new(
        working_dir: PathBuf,
        base_env: BTreeMap<String, String>,
        recreate_missing_workspace: bool,
    ) -> Self {
        Self::with_groups(
            working_dir,
            base_env,
            recreate_missing_workspace,
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            Arc::new(ProcessGroups::new(
                env::temp_dir()
                    .join("sandbox-driver-host-groups")
                    .join(registry::fresh_id()),
                true,
                true,
            )),
        )
    }

    pub(crate) fn with_groups(
        working_dir: PathBuf,
        base_env: BTreeMap<String, String>,
        recreate_missing_workspace: bool,
        #[cfg(any(target_os = "linux", target_os = "macos"))] groups: Arc<ProcessGroups>,
    ) -> Self {
        Self {
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            groups,
            working_dir,
            base_env,
            recreate_missing_workspace,
            drain_grace: DRAIN_GRACE,
        }
    }

    #[cfg(test)]
    fn with_drain_grace(mut self, grace: Duration) -> Self {
        self.drain_grace = grace;
        self
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

    async fn spawn_command(
        &self,
        program: &str,
        args: &[String],
        working_dir: Option<&str>,
        env: &BTreeMap<String, String>,
        stdin: Stdio,
    ) -> Result<HostChild> {
        if self.recreate_missing_workspace {
            fs::create_dir_all(&self.working_dir)
                .await
                .map_err(|error| Error::io("recreating managed workspace", error))?;
        }
        let configure = |command: &mut Command| {
            command.current_dir(self.resolve_dir(working_dir));
            command.env_clear();
            command.envs(effective_env(&self.base_env));
            command.envs(env);
            command
                .stdin(stdin)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
        };
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            self.groups.spawn(program, args, configure).await
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            let mut command = Command::new(program);
            command.args(args);
            configure(&mut command);
            #[cfg(unix)]
            command.process_group(0);
            command.kill_on_drop(true);
            command
                .spawn()
                .map_err(|error| Error::io("spawning host command", error))
        }
    }
}

#[cfg(unix)]
fn signal_process_group(child: &HostChild, signal: Signal) {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    child.signal(signal);
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
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
/// then SIGKILLs the group and the child directly: the stdio handle's
/// `terminate`.
///
/// The direct kill is the guarantee: a command that moved itself out of
/// its process group makes the group signals miss entirely (killpg on
/// an empty group is ESRCH), and the callers' subsequent `wait()` would
/// hang forever. SIGKILL to the immediate child always lands, and
/// `kill()` reaps it, so a completed terminate means a returned wait.
async fn terminate_process_group(child: &mut HostChild, grace: Duration) {
    #[cfg(unix)]
    {
        signal_process_group(child, Signal::SIGTERM);
        if time::timeout(grace, child.wait()).await.is_ok() {
            return;
        }
    }
    #[cfg(not(unix))]
    let _ = grace;
    kill_process_group(child).await;
}

/// SIGTERMs the process group, once, and returns: the
/// [`ExecControls::term`] path. Whether the command ends is the
/// command's business; the caller escalates to `kill` if it must.
fn term_process_group(child: &HostChild) {
    #[cfg(unix)]
    signal_process_group(child, Signal::SIGTERM);
    #[cfg(not(unix))]
    let _ = child;
}

/// SIGKILLs the process group and the child directly: the
/// [`ExecControls::kill`] path, the timeout, and a failing sink.
async fn kill_process_group(child: &mut HostChild) {
    #[cfg(unix)]
    signal_process_group(child, Signal::SIGKILL);
    let _ = child.kill().await;
}

enum PumpError {
    Sink,
    /// A transport failure mid-stream: output is incomplete, which must
    /// surface as an error, never as a clean exit with truncated output.
    Read(io::Error),
}

/// Reads one output stream to EOF, feeding the capture buffer and sink.
/// `progress` counts the chunks read, so the post-exit drain can tell a
/// silent pipe from a slow consumer.
async fn pump_stream(
    mut reader: impl AsyncRead + Unpin,
    stream: OutputStream,
    capture: &mut OutputCaptureBuffer,
    sink: Option<&OutputSink>,
    output_sanitization: OutputSanitization,
    progress: &AtomicU64,
) -> Result<(), PumpError> {
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
                            return Err(PumpError::Sink);
                        }
                    }
                }
                return Ok(());
            }
            Err(error) => return Err(PumpError::Read(error)),
            Ok(read) => {
                progress.fetch_add(1, Ordering::Relaxed);
                let chunk = sanitizer.push(&buffer[..read]);
                capture.push(&chunk);
                if !chunk.is_empty() {
                    if let Some(sink) = sink {
                        if sink(stream, chunk).await.is_err() {
                            return Err(PumpError::Sink);
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
        let streaming = self.run_streaming(spec, ExecControls::buffered()).await?;
        streaming.into_complete()
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
        let stdin_reader = controls.stdin_reader(spec);
        let mut child = self
            .spawn_command(
                &spec.program,
                &spec.args,
                spec.working_dir.as_deref(),
                &spec.env,
                if stdin_reader.is_some() {
                    Stdio::piped()
                } else {
                    Stdio::null()
                },
            )
            .await?;

        // Write-then-EOF, concurrently with output pumping so a large
        // write cannot deadlock against a full output pipe.
        let stdin_task = child
            .stdin
            .take()
            .zip(stdin_reader)
            .map(|(stdin, reader)| tokio::spawn(feed_stdin(stdin, reader)));

        let stdout = child.stdout.take().expect("stdout was piped");
        let stderr = child.stderr.take().expect("stderr was piped");
        let mut stdout_capture = OutputCaptureBuffer::new(controls.retained_output_limit);
        let mut stderr_capture = OutputCaptureBuffer::new(controls.retained_output_limit);
        let sink = controls.sink.as_ref();

        // The process, the stop tokens, and the timeout race until the
        // process ends; the pumps run alongside without gating any of
        // them, so a command that closes its own stdout/stderr (a
        // daemonizing child) is still bounded by the timeout. A `term`
        // signals and keeps waiting — the command may exit, or the
        // caller's `kill` may follow — so it records the termination
        // rather than ending the race. Remaining output is drained after
        // the process ends, until the pipes have been silent for
        // `drain_grace`.
        let mut read_error: Option<io::Error> = None;
        let mut drain_truncated = false;
        let progress = AtomicU64::new(0);
        let (termination, status) = {
            let mut pumps = pin!(async {
                tokio::try_join!(
                    pump_stream(
                        stdout,
                        OutputStream::Stdout,
                        &mut stdout_capture,
                        sink,
                        spec.output_sanitization,
                        &progress,
                    ),
                    pump_stream(
                        stderr,
                        OutputStream::Stderr,
                        &mut stderr_capture,
                        sink,
                        spec.output_sanitization,
                        &progress,
                    ),
                )
            });
            let mut pumps_done = false;

            let mut termed = pin!(stop_signal(controls.term.as_ref()));
            let mut killed = pin!(stop_signal(controls.kill.as_ref()));
            let mut term_fired = false;

            let mut timeout = pin!(async {
                match spec.timeout {
                    Some(timeout) => time::sleep(timeout).await,
                    None => future::pending().await,
                }
            });

            let (mut termination, status) = loop {
                tokio::select! {
                    outcome = &mut pumps, if !pumps_done => {
                        pumps_done = true;
                        if let Err(error) = outcome {
                            if let PumpError::Read(error) = error {
                                read_error = Some(error);
                            }
                            drain_truncated = true;
                            kill_process_group(&mut child).await;
                            break (Termination::Cancelled, None);
                        }
                    }
                    wait_result = child.wait() => {
                        let status = wait_result.map_err(|error| {
                            Error::io("waiting for exec process", error)
                        })?;
                        let termination = if term_fired {
                            Termination::Cancelled
                        } else {
                            Termination::Exited
                        };
                        break (termination, Some(status));
                    }
                    () = &mut termed, if !term_fired => {
                        term_fired = true;
                        term_process_group(&child);
                    }
                    () = &mut killed => {
                        kill_process_group(&mut child).await;
                        break (Termination::Killed, None);
                    }
                    () = &mut timeout => {
                        kill_process_group(&mut child).await;
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
                // The leader can exit while descendants keep its pipes open
                // or a sink stays blocked. Keep the caller's stop controls and
                // the original timeout live until those pumps finish too.
                // The deadline measures silence: output still arriving, however
                // slowly the sink takes it, re-arms it, so a loaded consumer
                // never loses the tail of a command that already exited.
                let mut seen = progress.load(Ordering::Relaxed);
                let mut drain_deadline = pin!(time::sleep(self.drain_grace));
                loop {
                    if matches!(termination, Termination::Killed | Termination::TimedOut) {
                        drain_truncated = true;
                        break;
                    }
                    tokio::select! {
                        biased;
                        () = &mut killed => {
                            kill_process_group(&mut child).await;
                            termination = Termination::Killed;
                        }
                        () = &mut timeout => {
                            kill_process_group(&mut child).await;
                            termination = Termination::TimedOut;
                        }
                        () = &mut termed, if !term_fired => {
                            term_fired = true;
                            term_process_group(&child);
                            termination = Termination::Cancelled;
                        }
                        outcome = &mut pumps => {
                            if let Err(error) = outcome {
                                if let PumpError::Read(error) = error {
                                    read_error = Some(error);
                                }
                                kill_process_group(&mut child).await;
                                termination = Termination::Cancelled;
                                drain_truncated = true;
                            }
                            break;
                        }
                        () = &mut drain_deadline => {
                            let now = progress.load(Ordering::Relaxed);
                            if now != seen {
                                seen = now;
                                drain_deadline
                                    .as_mut()
                                    .reset(time::Instant::now() + self.drain_grace);
                                continue;
                            }
                            drain_truncated = true;
                            break;
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
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        let mut result = ExecResult::from_shell_status(termination, exit_code, started.elapsed());
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        let mut result = ExecResult::new(termination, exit_code, started.elapsed());
        result.signal = exit_signal.or(result.signal);
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
        let mut child = self
            .spawn_command(
                &spec.program,
                &spec.args,
                spec.working_dir.as_deref(),
                &spec.env,
                Stdio::piped(),
            )
            .await?;
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
    fn supervise(mut child: HostChild) -> Self {
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

#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod tests {
    use sandbox_driver::{SandboxProvider, SandboxSource, SandboxSpec};
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::task::spawn_blocking;

    use super::*;
    use crate::HostProvider;
    use crate::observation::group_is_live;

    async fn wait_for_group_exit(pgid: i32) {
        time::timeout(Duration::from_secs(3), async {
            while spawn_blocking(move || group_is_live(pgid))
                .await
                .expect("observe process group")
            {
                time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .expect("the final temporary owner releases its sentinel");
    }

    fn expected_seq(count: usize) -> Vec<u8> {
        (1..=count)
            .map(|n| format!("{n}\n"))
            .collect::<String>()
            .into_bytes()
    }

    /// The consumer is slower than the whole drain grace, but it keeps
    /// taking output: every byte the exited command wrote arrives.
    #[tokio::test]
    async fn a_slow_consumer_receives_every_byte_after_the_process_exits() {
        let exec = HostExec::new(env::temp_dir(), BTreeMap::new(), false)
            .with_drain_grace(Duration::from_millis(150));
        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink_seen = Arc::clone(&seen);
        let controls = ExecControls {
            sink: Some(Arc::new(move |stream, chunk| {
                let seen = Arc::clone(&sink_seen);
                Box::pin(async move {
                    time::sleep(Duration::from_millis(60)).await;
                    if stream == OutputStream::Stdout {
                        seen.lock().unwrap().extend_from_slice(&chunk);
                    }
                    Ok(())
                })
            })),
            retained_output_limit: Some(0),
            ..ExecControls::buffered()
        };
        let spec = ExecSpec::new("seq")
            .args(["1", "20000"])
            .timeout(Duration::from_secs(60));
        let streaming = exec.run_streaming(&spec, controls).await.unwrap();
        assert!(streaming.result.success());
        assert!(!streaming.stdout_capture.truncated);
        assert_eq!(*seen.lock().unwrap(), expected_seq(20000));
    }

    /// A grandchild that keeps the pipe open without writing ends the
    /// drain after the grace, reported as truncated output.
    #[tokio::test]
    async fn a_silent_grandchild_ends_the_drain_after_the_grace() {
        let exec = HostExec::new(env::temp_dir(), BTreeMap::new(), false)
            .with_drain_grace(Duration::from_millis(200));
        let started = Instant::now();
        let spec =
            ExecSpec::bash("echo leader; sleep 30 & exit 0").timeout(Duration::from_secs(60));
        let streaming = exec
            .run_streaming(&spec, ExecControls::buffered())
            .await
            .unwrap();
        assert_eq!(streaming.result.stdout, b"leader\n");
        assert!(streaming.stdout_capture.truncated);
        assert!(started.elapsed() < Duration::from_secs(5));
        drop(exec);
    }

    #[tokio::test]
    async fn standalone_exec_releases_completed_process_groups_on_drop() {
        let exec = HostExec::new(env::temp_dir(), BTreeMap::new(), false);
        let result = exec.run(&ExecSpec::bash("echo $PPID")).await.unwrap();
        let pgid = result.stdout_lossy().trim().parse().unwrap();
        drop(exec);
        wait_for_group_exit(pgid).await;
    }

    #[tokio::test]
    async fn standalone_stdio_owns_its_process_after_the_executor_drops() {
        let exec = HostExec::new(env::temp_dir(), BTreeMap::new(), false);
        let mut process = exec
            .spawn_stdio(&SpawnSpec::new("sh").args(["-c", "echo $PPID; exec cat"]))
            .await
            .unwrap();
        drop(exec);
        let mut output = BufReader::new(process.stdout);
        let mut line = String::new();
        output.read_line(&mut line).await.unwrap();
        let pgid = line.trim().parse().unwrap();
        process.stdin.write_all(b"still alive\n").await.unwrap();
        line.clear();
        time::timeout(Duration::from_secs(3), output.read_line(&mut line))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(line, "still alive\n");
        process.handle.terminate().await;
        wait_for_group_exit(pgid).await;
    }

    #[tokio::test]
    async fn only_durable_providers_keep_groups_after_the_last_handle_drops() {
        for durable in [false, true] {
            let root = env::temp_dir().join(registry::fresh_id());
            let provider = if durable {
                HostProvider::with_registry(&root).await.unwrap()
            } else {
                HostProvider::new()
            };
            let sandbox = provider
                .create(&SandboxSpec::new(SandboxSource::HostDirectory), None)
                .await
                .unwrap();
            let id = sandbox.id().clone();
            let workspace = sandbox.working_directory().to_owned();
            let result = sandbox
                .exec()
                .run(&ExecSpec::bash("echo $PPID"))
                .await
                .unwrap();
            let pgid = result.stdout_lossy().trim().parse().unwrap();
            drop(sandbox);
            drop(provider);
            if durable {
                assert!(spawn_blocking(move || group_is_live(pgid)).await.unwrap());
                HostProvider::with_registry(&root)
                    .await
                    .unwrap()
                    .delete(&id, None)
                    .await
                    .unwrap();
                fs::remove_dir_all(root).await.unwrap();
            } else {
                fs::remove_dir_all(workspace).await.unwrap();
            }
            wait_for_group_exit(pgid).await;
        }
    }
}
