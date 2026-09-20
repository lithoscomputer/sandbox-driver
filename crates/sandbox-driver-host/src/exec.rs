use std::collections::BTreeMap;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::{Pin, pin};
use std::process::{ExitStatus, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use std::{env, future, io};

use async_trait::async_trait;
use sandbox_driver::{
    Error, Exec, ExecControls, ExecResult, ExecSpec, ExecStreamingResult, OutputCaptureBuffer,
    OutputSanitizer, OutputSink, OutputStream, Result, SpawnSpec, StderrTail, StdioProcess,
    StdioProcessHandle, Termination, feed_stdin, run_with_stop_grace, stop_signal,
};
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::process::{ChildStderr, ChildStdout, Command};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio::{fs, time};

use crate::fence::{HostChild, ProcessGroups, exec_result};
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
        groups: Arc<ProcessGroups>,
    ) -> Self {
        Self {
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
        self.groups.spawn(program, args, configure).await
    }
}

enum PumpError {
    Sink,
    /// A transport failure mid-stream: output is incomplete, which must
    /// surface as an error, never as a clean exit with truncated output.
    Read(io::Error),
}

/// One output stream's pump: reads the pipe to EOF and delivers each chunk
/// to the capture buffer and the sink.
struct OutputPump<'a> {
    stream:    OutputStream,
    sanitizer: OutputSanitizer,
    capture:   &'a mut OutputCaptureBuffer,
    sink:      Option<&'a OutputSink>,
    /// Counts the chunks read, so the post-exit drain can tell a silent
    /// pipe from a slow consumer.
    progress:  &'a AtomicU64,
}

impl OutputPump<'_> {
    /// Captures one sanitized chunk and hands it to the sink; the sink
    /// only sees chunks with bytes in them.
    async fn deliver(&mut self, chunk: Vec<u8>) -> Result<(), PumpError> {
        self.capture.push(&chunk);
        match self.sink {
            Some(sink) if !chunk.is_empty() => {
                sink(self.stream, chunk).await.map_err(|_| PumpError::Sink)
            }
            _ => Ok(()),
        }
    }

    async fn run(mut self, mut reader: impl AsyncRead + Unpin) -> Result<(), PumpError> {
        let mut buffer = [0u8; 8192];
        loop {
            match reader.read(&mut buffer).await {
                Ok(0) => {
                    let chunk = self.sanitizer.finish();
                    return self.deliver(chunk).await;
                }
                Err(error) => return Err(PumpError::Read(error)),
                Ok(read) => {
                    self.progress.fetch_add(1, Ordering::Relaxed);
                    let chunk = self.sanitizer.push(&buffer[..read]);
                    self.deliver(chunk).await?;
                }
            }
        }
    }
}

/// A spawned command with its pipes taken: the child to race, the stdin
/// writer task when the spec has input, and the output pipes to pump.
struct Wired {
    child:      HostChild,
    stdin_task: Option<JoinHandle<Result<()>>>,
    stdout:     ChildStdout,
    stderr:     ChildStderr,
}

/// Where the exec race stands.
#[derive(Clone, Copy)]
enum Phase {
    /// The process is running; its exit, or a stop, ends this phase.
    Running,
    /// The process has exited. Its remaining output drains until the pumps
    /// finish or the pipes stay silent for the grace; `seen` is the pump
    /// progress when the drain deadline was last armed.
    Draining { status: ExitStatus, seen: u64 },
}

impl Phase {
    /// Kills the process group and settles the race as `termination`. The
    /// exit status is already known once the process has exited; otherwise
    /// it is awaited now that the group has been killed.
    async fn stop(
        self,
        child: &mut HostChild,
        termination: Termination,
    ) -> Result<(Termination, ExitStatus)> {
        child.kill().await;
        let status = match self {
            Self::Running => child
                .wait()
                .await
                .map_err(|error| Error::io("waiting for exec process", error))?,
            Self::Draining { status, .. } => status,
        };
        Ok((termination, status))
    }
}

/// How a process that ended on its own is reported: cancelled when the
/// caller's `term` was sent, exited otherwise.
fn natural_termination(term_fired: bool) -> Termination {
    if term_fired {
        Termination::Cancelled
    } else {
        Termination::Exited
    }
}

/// How the race ended.
struct Raced {
    termination:  Termination,
    status:       ExitStatus,
    /// How the pumps ended, or `None` when the race ended before both
    /// pumps had finished.
    pump_outcome: Option<Result<(), PumpError>>,
}

fn assemble_result(
    termination: Termination,
    status: ExitStatus,
    duration: Duration,
    drain_truncated: bool,
    stdout_capture: OutputCaptureBuffer,
    stderr_capture: OutputCaptureBuffer,
) -> ExecStreamingResult {
    let (stdout_bytes, mut stdout_stats) = stdout_capture.into_parts();
    let (stderr_bytes, mut stderr_stats) = stderr_capture.into_parts();
    if drain_truncated {
        stdout_stats.truncated = true;
        stderr_stats.truncated = true;
    }
    let mut result = exec_result(termination, status, duration);
    result.stdout = stdout_bytes;
    result.stderr = stderr_bytes;

    let mut streaming = ExecStreamingResult::new(result);
    streaming.streams_separated = true;
    streaming.live_streaming = true;
    streaming.stdout_capture = stdout_stats;
    streaming.stderr_capture = stderr_stats;
    streaming
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
        run_with_stop_grace(spec, controls, |spec, controls| async move {
            self.run_signals(&spec, controls).await
        })
        .await
    }

    async fn spawn_stdio(&self, spec: &SpawnSpec) -> Result<StdioProcess> {
        self.spawn_stdio_raw(spec).await
    }
}

impl HostExec {
    /// Runs the command under raw stop signals; the trait method wraps
    /// this in the spec's stop grace.
    async fn run_signals(
        &self,
        spec: &ExecSpec,
        controls: ExecControls,
    ) -> Result<ExecStreamingResult> {
        let started = Instant::now();
        let Wired {
            mut child,
            stdin_task,
            stdout,
            stderr,
        } = self.spawn_and_wire(spec, &controls).await?;
        let mut stdout_capture = OutputCaptureBuffer::new(controls.retained_output_limit);
        let mut stderr_capture = OutputCaptureBuffer::new(controls.retained_output_limit);
        let sink = controls.sink.as_ref();
        let progress = AtomicU64::new(0);
        // Pinned here, not inside `race`, so the race future stays small
        // while the pumps own their read buffers. The block ends the pumps'
        // borrow of the captures once the race has settled.
        let Raced {
            termination,
            status,
            pump_outcome,
        } = {
            let mut pumps = pin!(async {
                tokio::try_join!(
                    OutputPump {
                        stream: OutputStream::Stdout,
                        sanitizer: OutputSanitizer::new(spec.output_sanitization),
                        capture: &mut stdout_capture,
                        sink,
                        progress: &progress,
                    }
                    .run(stdout),
                    OutputPump {
                        stream: OutputStream::Stderr,
                        sanitizer: OutputSanitizer::new(spec.output_sanitization),
                        capture: &mut stderr_capture,
                        sink,
                        progress: &progress,
                    }
                    .run(stderr),
                )?;
                Ok::<(), PumpError>(())
            });
            self.race(
                &mut child,
                &controls,
                spec.timeout,
                pumps.as_mut(),
                &progress,
            )
            .await?
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
        // Pumps that finished cleanly are the only complete output. Every
        // other way out of the race (a stop, the timeout, a failed sink or
        // read, or a pipe that stayed silent after exit) left output unread.
        let drain_truncated = !matches!(pump_outcome, Some(Ok(())));
        if let Some(Err(PumpError::Read(error))) = pump_outcome {
            return Err(Error::io("reading exec output", error));
        }
        Ok(assemble_result(
            termination,
            status,
            started.elapsed(),
            drain_truncated,
            stdout_capture,
            stderr_capture,
        ))
    }

    /// Spawns the command and takes its pipes: stdin goes to a writer task
    /// when the spec has input, stdout and stderr to the caller's pumps.
    async fn spawn_and_wire(&self, spec: &ExecSpec, controls: &ExecControls) -> Result<Wired> {
        let stdin_reader = controls.stdin_reader(spec);
        let mut child = self
            .spawn_command(
                &spec.program,
                &spec.args,
                spec.working_dir.as_deref(),
                &spec.launch_env(),
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
        Ok(Wired {
            child,
            stdin_task,
            stdout,
            stderr,
        })
    }

    /// Races the process against the stop tokens, the timeout, and the
    /// output pumps until it has ended and its output has drained.
    ///
    /// The pumps run alongside without gating the process, so a command
    /// that closes its own stdout/stderr (a daemonizing child) is still
    /// bounded by the timeout. A `term` signals and keeps waiting — the
    /// command may exit, or the caller's `kill` may follow — so it records
    /// the termination rather than ending the race. Once the process has
    /// ended, the caller's stop controls and the original timeout stay
    /// live while the remaining output drains: the leader can exit while
    /// descendants keep its pipes open or a sink stays blocked. The drain
    /// deadline measures silence: output still arriving, however slowly
    /// the sink takes it, re-arms it, so a loaded consumer never loses the
    /// tail of a command that already exited.
    async fn race(
        &self,
        child: &mut HostChild,
        controls: &ExecControls,
        timeout: Option<Duration>,
        mut pumps: Pin<&mut impl Future<Output = Result<(), PumpError>>>,
        progress: &AtomicU64,
    ) -> Result<Raced> {
        let mut pump_outcome = None;
        let mut termed = pin!(stop_signal(controls.term.as_ref()));
        let mut killed = pin!(stop_signal(controls.kill.as_ref()));
        let mut term_fired = false;
        let mut timeout = pin!(async {
            match timeout {
                Some(timeout) => time::sleep(timeout).await,
                None => future::pending().await,
            }
        });
        // Armed when the process exits; disabled until then.
        let mut drain_deadline = pin!(time::sleep(self.drain_grace));
        let mut phase = Phase::Running;

        let (termination, status) = loop {
            tokio::select! {
                biased;
                () = &mut killed => break phase.stop(child, Termination::Killed).await?,
                () = &mut timeout => break phase.stop(child, Termination::TimedOut).await?,
                () = &mut termed, if !term_fired => {
                    term_fired = true;
                    child.term();
                }
                outcome = &mut pumps, if pump_outcome.is_none() => {
                    let failed = outcome.is_err();
                    pump_outcome = Some(outcome);
                    if failed {
                        break phase.stop(child, Termination::Cancelled).await?;
                    }
                    if let Phase::Draining { status, .. } = phase {
                        break (natural_termination(term_fired), status);
                    }
                }
                wait_result = child.wait(), if matches!(phase, Phase::Running) => {
                    let status = wait_result
                        .map_err(|error| Error::io("waiting for exec process", error))?;
                    if pump_outcome.is_some() {
                        break (natural_termination(term_fired), status);
                    }
                    drain_deadline
                        .as_mut()
                        .reset(time::Instant::now() + self.drain_grace);
                    phase = Phase::Draining {
                        status,
                        seen: progress.load(Ordering::Relaxed),
                    };
                }
                () = &mut drain_deadline, if matches!(phase, Phase::Draining { .. }) => {
                    if let Phase::Draining { status, seen } = &mut phase {
                        let now = progress.load(Ordering::Relaxed);
                        if now == *seen {
                            break (natural_termination(term_fired), *status);
                        }
                        *seen = now;
                        drain_deadline
                            .as_mut()
                            .reset(time::Instant::now() + self.drain_grace);
                    }
                }
            }
        };
        Ok(Raced {
            termination,
            status,
            pump_outcome,
        })
    }

    #[tracing::instrument(skip_all, fields(provider_kind = "host"), err)]
    async fn spawn_stdio_raw(&self, spec: &SpawnSpec) -> Result<StdioProcess> {
        let mut child = self
            .spawn_command(
                &spec.program,
                &spec.args,
                spec.working_dir.as_deref(),
                &spec.launch_env(),
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
                    child.terminate(TERM_GRACE).await;
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

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    fn expected_seq(count: usize) -> Vec<u8> {
        let mut lines = String::new();
        for n in 1..=count {
            lines.push_str(&n.to_string());
            lines.push('\n');
        }
        lines.into_bytes()
    }

    /// The consumer is slower than the whole drain grace, but it keeps
    /// taking output: every byte the exited command wrote arrives.
    #[tokio::test]
    async fn a_slow_consumer_receives_every_byte_after_the_process_exits() {
        let exec = HostExec::new(env::temp_dir(), BTreeMap::new(), false)
            .with_drain_grace(Duration::from_millis(150));
        let seen = Arc::new(Mutex::new(Vec::new()));
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
}
