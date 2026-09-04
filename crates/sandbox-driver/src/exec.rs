use std::collections::BTreeMap;
use std::future::Future;
use std::io::Cursor;
use std::pin::Pin;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;
use std::{fmt, future, io};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, copy};
use tokio_util::sync::CancellationToken;

use crate::capabilities::Capability;
use crate::error::{Error, Result};
use crate::sanitize::OutputSanitization;

/// The interpreter [`ExecSpec::bash`] names, resolved through `PATH`
/// (NixOS has no `/bin/bash`).
const BASH: &str = "bash";
const BASH_COMMAND_FLAG: &str = "-c";
/// Bash sources this file before running `-c` source; the helper blanks
/// it so a sandbox environment cannot run code ahead of the script.
pub const BASH_ENV_VAR: &str = "BASH_ENV";

/// Command execution inside a sandbox.
///
/// # The exec contract (normative)
///
/// A spec names a program and its arguments, and a provider executes that
/// vector directly, with `execvp` semantics: `program` is resolved through
/// the command's `PATH` when it contains no slash, and every argument
/// reaches the process unchanged. No shell is involved, so nothing is
/// split, globbed, or expanded. Buffered and streaming execution must not
/// differ in how the vector is run.
///
/// A caller who wants shell semantics asks for them with
/// [`ExecSpec::bash`], which is the one place the Bash contract lives. The
/// [`crate::run_bash_probe`] helper verifies that a sandbox can serve it,
/// and belongs in every provider's conformance run because the
/// exec-derived facets are Bash scripts.
#[async_trait]
pub trait Exec: Send + Sync {
    /// Runs a command to completion, buffering output.
    async fn run(&self, spec: &ExecSpec) -> Result<ExecResult>;

    /// Runs a command, delivering output through `controls.sink` as it
    /// arrives. Providers that cannot stream fall back to buffered
    /// execution, replay the output through the sink, and report
    /// `live_streaming: false`.
    ///
    /// Control contracts: cancellation resolves the call normally with
    /// [`Termination::Cancelled`] after a best-effort process-group kill.
    /// The sink is awaited per chunk — a slow consumer backpressures the
    /// read loop. Output beyond `controls.retained_output_limit` is still
    /// drained (and counted in [`CaptureStats::omitted_bytes`]), never left
    /// to block the process. A sink error cancels the execution.
    ///
    /// `controls.kill` ends the command with [`Termination::Killed`] and no
    /// grace; `controls.grace` sets the cancel ladder's SIGTERM-to-SIGKILL
    /// wait. A provider that cannot separate the two treats `kill` as
    /// `cancel` and ignores `grace`. `controls.stdin` streams standard
    /// input for the life of the command; it is capability-gated on
    /// `exec.stdin_stream` and rejected with [`Error::Unsupported`] where
    /// undeclared.
    ///
    /// A provider that does not support stdin or cancellation must reject
    /// a call that supplies them with [`Error::Unsupported`]
    /// (`exec.stdin` / `exec.cancel`) — never run the command with the
    /// input silently dropped. Capability preflight is the supported way
    /// to avoid the error.
    async fn run_streaming(
        &self,
        spec: &ExecSpec,
        controls: ExecControls,
    ) -> Result<ExecStreamingResult>;

    /// Spawns a long-lived bidirectional stdio process (ACP backends).
    ///
    /// Capability-gated on `exec.stdio_process`; the default returns
    /// [`Error::Unsupported`].
    async fn spawn_stdio(&self, spec: &SpawnSpec) -> Result<StdioProcess> {
        let _ = spec;
        Err(Error::unsupported(Capability::ExecStdioProcess))
    }
}

/// Serializable execution request — exactly what crosses the JSON-RPC
/// boundary. Process-local control objects travel in [`ExecControls`].
///
/// `Debug` redacts the arguments (they can embed credentialed URLs — the
/// git credential rewrite does), env values, and stdin, so tracing a
/// spec can never leak them; fabro enforced the same rule by omitting
/// `Debug` entirely.
#[derive(Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct ExecSpec {
    /// The executable, resolved through the command's `PATH` when it has
    /// no slash; see the trait-level contract.
    pub program:             String,
    /// Arguments after the program, passed unchanged.
    pub args:                Vec<String>,
    /// `None` waits forever. [`ExecSpec::new`] starts at
    /// [`ExecSpec::DEFAULT_TIMEOUT`]; opt out with
    /// [`ExecSpec::no_timeout`].
    pub timeout:             Option<Duration>,
    pub working_dir:         Option<String>,
    pub env:                 BTreeMap<String, String>,
    /// Written to the process then closed for EOF. A broken pipe while
    /// writing (the `head -1` case) is not an error.
    pub stdin:               Option<Vec<u8>>,
    /// Output policy for buffered results and streaming sink chunks. PTY
    /// sessions and [`Exec::spawn_stdio`] remain raw.
    #[serde(default)]
    pub output_sanitization: OutputSanitization,
}

impl ExecSpec {
    /// Applied by [`ExecSpec::new`]: generous enough for a long build,
    /// but a wedged command cannot hang a caller forever. fabro's exec
    /// API made every caller pick a timeout; the default keeps that
    /// fail-safe without forcing the choice.
    pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(3600);

    /// A spec that runs `program` with no arguments; add them with
    /// [`ExecSpec::arg`] or [`ExecSpec::args`].
    pub fn new(program: impl Into<String>) -> Self {
        Self {
            program:             program.into(),
            args:                Vec::new(),
            timeout:             Some(Self::DEFAULT_TIMEOUT),
            working_dir:         None,
            env:                 BTreeMap::new(),
            stdin:               None,
            output_sanitization: OutputSanitization::Raw,
        }
    }

    /// A spec that evaluates `script` as Bash source: the argv
    /// `bash -c <script>`, non-login, with Bash's options untouched (no
    /// `errexit`, no `pipefail`, no POSIX mode) and `BASH_ENV` blanked in
    /// the spec env so no startup file runs first. A script wanting other
    /// options sets them itself. This is the Bash contract; it holds
    /// wherever the sandbox has `bash` on `PATH`, which
    /// [`crate::run_bash_probe`] verifies.
    pub fn bash(script: impl Into<String>) -> Self {
        Self::new(BASH)
            .args([BASH_COMMAND_FLAG, &script.into()])
            .env_var(BASH_ENV_VAR, "")
    }

    #[must_use]
    pub fn arg(mut self, arg: impl Into<String>) -> Self {
        self.args.push(arg.into());
        self
    }

    #[must_use]
    pub fn args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.args.extend(args.into_iter().map(Into::into));
        self
    }

    /// Deliberately unbounded: wait forever on the command.
    #[must_use]
    pub fn no_timeout(mut self) -> Self {
        self.timeout = None;
        self
    }

    #[must_use]
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    #[must_use]
    pub fn working_dir(mut self, dir: impl Into<String>) -> Self {
        self.working_dir = Some(dir.into());
        self
    }

    #[must_use]
    pub fn env_var(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.env.insert(key.into(), value.into());
        self
    }

    #[must_use]
    pub fn stdin(mut self, bytes: Vec<u8>) -> Self {
        self.stdin = Some(bytes);
        self
    }

    #[must_use]
    pub fn output_sanitization(mut self, policy: OutputSanitization) -> Self {
        self.output_sanitization = policy;
        self
    }
}

impl fmt::Debug for ExecSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExecSpec")
            .field("program", &self.program)
            .field("args", &"<redacted>")
            .field("timeout", &self.timeout)
            .field("working_dir", &self.working_dir)
            .field("env_keys", &self.env.keys().collect::<Vec<_>>())
            .field("stdin_bytes", &self.stdin.as_ref().map(Vec::len))
            .field("output_sanitization", &self.output_sanitization)
            .finish()
    }
}

/// Which output stream a chunk belongs to.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutputStream {
    Stdout,
    Stderr,
}

/// Async output sink for streaming execution. Awaited per chunk; returning
/// an error cancels the execution.
pub type OutputSink = Arc<
    dyn Fn(OutputStream, Vec<u8>) -> Pin<Box<dyn Future<Output = Result<()>> + Send>> + Send + Sync,
>;

/// Process-local controls for [`Exec::run_streaming`]. Never serialized;
/// on the wire these map to negotiated execution IDs.
///
/// Two stop levels: `cancel` is the polite ladder (SIGTERM to the process
/// group, `grace`, then SIGKILL) and resolves with
/// [`Termination::Cancelled`]; `kill` skips the grace and SIGKILLs the
/// group at once, resolving with [`Termination::Killed`]. A provider that
/// cannot distinguish the two treats `kill` as `cancel`. `grace` overrides
/// the provider's default (two seconds); a provider that cannot honor a
/// grace ignores it.
#[derive(Clone, Default)]
pub struct ExecControls {
    pub cancel:                Option<CancellationToken>,
    /// Immediate SIGKILL of the process group, no grace.
    pub kill:                  Option<CancellationToken>,
    /// How long the cancel ladder waits between SIGTERM and SIGKILL.
    pub grace:                 Option<Duration>,
    /// Streamed standard input, written to the process as it becomes
    /// readable and closed at its EOF. Mutually exclusive with
    /// [`ExecSpec::stdin`]; capability-gated on `exec.stdin_stream`.
    pub stdin:                 Option<StdinSource>,
    pub sink:                  Option<OutputSink>,
    /// Retention cap for the buffered copy in the result (head + tail);
    /// output beyond it is drained and counted, not kept.
    pub retained_output_limit: Option<usize>,
}

impl ExecControls {
    /// The standard input the command should be fed, if any: the streamed
    /// source when set, else the fixed [`ExecSpec::stdin`] bytes. The two
    /// never coexist (the control-plane contract), so a stream wins when
    /// both are given; a source another consumer already took reads as
    /// empty. Providers feed the reader with [`feed_stdin`].
    pub fn stdin_reader(&self, spec: &ExecSpec) -> Option<StdinReader> {
        match (&self.stdin, &spec.stdin) {
            (Some(source), _) => Some(
                source
                    .take()
                    .unwrap_or_else(|| Box::pin(Cursor::new(Vec::new()))),
            ),
            (None, Some(bytes)) => Some(Box::pin(Cursor::new(bytes.clone()))),
            (None, None) => None,
        }
    }

    /// Resolves when either stop token fires — the one-level view for a
    /// provider that treats `kill` as `cancel`. Never resolves when
    /// neither token is set.
    pub async fn stop_requested(&self) {
        tokio::select! {
            () = stop_signal(self.cancel.as_ref()) => {}
            () = stop_signal(self.kill.as_ref()) => {}
        }
    }
}

impl fmt::Debug for ExecControls {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExecControls")
            .field("cancel", &self.cancel.is_some())
            .field("kill", &self.kill.is_some())
            .field("grace", &self.grace)
            .field("stdin", &self.stdin.is_some())
            .field("sink", &self.sink.is_some())
            .field("retained_output_limit", &self.retained_output_limit)
            .finish()
    }
}

/// Resolves when an optional token is cancelled; never resolves when
/// there is no token, so it slots into a `select!` arm unconditionally.
pub async fn stop_signal(token: Option<&CancellationToken>) {
    match token {
        Some(token) => token.cancelled().await,
        None => future::pending().await,
    }
}

/// The boxed reader a [`StdinSource`] hands to the running provider.
pub type StdinReader = Pin<Box<dyn AsyncRead + Send>>;

/// A streamed standard input for [`ExecControls::stdin`].
///
/// The reader is handed over exactly once: the provider that runs the
/// command takes it, so a cloned `ExecControls` shares one source. The
/// source is closed for EOF when the reader ends; a process that stops
/// reading its input disconnecting the pipe is not an error.
#[derive(Clone)]
pub struct StdinSource {
    reader: Arc<Mutex<Option<StdinReader>>>,
}

impl StdinSource {
    pub fn new(reader: impl AsyncRead + Send + 'static) -> Self {
        Self {
            reader: Arc::new(Mutex::new(Some(Box::pin(reader)))),
        }
    }

    /// Takes the reader; `None` once a provider has already taken it.
    pub fn take(&self) -> Option<StdinReader> {
        self.reader
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
    }
}

/// Copies `reader` into the process stdin, then closes it for EOF. A
/// command that stops reading its input (`head -1`) disconnecting the
/// pipe is normal; any other failure means the command saw truncated
/// input and must not pass silently.
pub async fn feed_stdin<W: AsyncWrite + Unpin>(
    mut stdin: W,
    mut reader: StdinReader,
) -> Result<()> {
    fn is_disconnect(error: &io::Error) -> bool {
        matches!(
            error.kind(),
            io::ErrorKind::BrokenPipe
                | io::ErrorKind::ConnectionReset
                | io::ErrorKind::ConnectionAborted
        )
    }
    if let Err(error) = copy(&mut reader, &mut stdin).await {
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

impl fmt::Debug for StdinSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StdinSource").finish_non_exhaustive()
    }
}

/// How a command ended.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Termination {
    Exited,
    TimedOut,
    /// Ended by [`ExecControls::cancel`] (or a failing sink).
    Cancelled,
    /// Ended by [`ExecControls::kill`].
    Killed,
    #[serde(other)]
    Unknown,
}

/// Result of a buffered command run. Output is bytes: sandbox output is
/// not guaranteed UTF-8.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub struct ExecResult {
    pub stdout:      Vec<u8>,
    pub stderr:      Vec<u8>,
    /// Meaningful only when `termination` is [`Termination::Exited`].
    /// A timed-out or cancelled run may still carry a code the provider
    /// happened to observe (a trapped SIGTERM exiting 0, a kill
    /// wrapper's 143) — never treat `Some(0)` alone as success; use
    /// [`ExecResult::success`], which checks the termination.
    pub exit_code:   Option<i32>,
    /// The signal that ended the command's process, when the provider
    /// observed one — a foreign `kill`, or the provider's own cancel
    /// ladder — whatever the `termination`. `None` when the process
    /// exited on its own or the provider cannot tell; a provider that only
    /// sees a shell's `128 + N` convention decodes it with
    /// [`ExecResult::from_shell_status`].
    #[serde(default)]
    pub signal:      Option<i32>,
    pub termination: Termination,
    pub duration:    Duration,
}

impl ExecResult {
    pub fn new(termination: Termination, exit_code: Option<i32>, duration: Duration) -> Self {
        Self {
            stdout: Vec::new(),
            stderr: Vec::new(),
            exit_code,
            signal: None,
            termination,
            duration,
        }
    }

    /// Reads a shell-reported status: `128 + N` means the child died of
    /// signal `N`, anything else is an ordinary exit code. The code is
    /// kept intact either way. The signal is decoded for every
    /// termination: a foreign `kill` on a natural exit, and the signal the
    /// provider's own ladder landed on a cancelled, killed, or timed-out
    /// command — `termination` says who stopped it, `signal` says how.
    /// A process that deliberately exits with such a code is
    /// indistinguishable; the convention is the best a wrapper shell can
    /// report.
    pub fn from_shell_status(
        termination: Termination,
        status: Option<i32>,
        duration: Duration,
    ) -> Self {
        let mut result = Self::new(termination, status, duration);
        if let Some(code) = status {
            if (129..=192).contains(&code) {
                result.signal = Some(code - 128);
            }
        }
        result
    }

    /// Stdout decoded lossily for display.
    pub fn stdout_lossy(&self) -> String {
        String::from_utf8_lossy(&self.stdout).into_owned()
    }

    /// Stderr decoded lossily for display.
    pub fn stderr_lossy(&self) -> String {
        String::from_utf8_lossy(&self.stderr).into_owned()
    }

    /// Whether the command exited on its own with code 0.
    pub fn success(&self) -> bool {
        self.termination == Termination::Exited && self.exit_code == Some(0)
    }
}

/// Retention accounting for one captured stream. Counts describe bytes after
/// [`ExecSpec::output_sanitization`] has been applied.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(default)]
pub struct CaptureStats {
    pub observed_bytes: usize,
    pub retained_bytes: usize,
    pub omitted_bytes:  usize,
    /// Bytes were lost *beyond* this accounting: the provider could not
    /// finish draining the stream (a post-exit drain bound expired), so
    /// `observed_bytes` and `omitted_bytes` undercount the real output.
    /// Retention-cap omission is not truncation — `omitted_bytes`
    /// already counts it.
    #[serde(default)]
    pub truncated:      bool,
}

impl CaptureStats {
    /// Accounting for a fully retained buffer: everything observed was
    /// kept.
    pub fn complete(bytes: usize) -> Self {
        Self {
            observed_bytes: bytes,
            retained_bytes: bytes,
            omitted_bytes:  0,
            truncated:      false,
        }
    }
}

/// Result of a streaming run, with honesty flags: degradations (combined
/// output, buffered replay) are reported, not hidden.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub struct ExecStreamingResult {
    pub result:            ExecResult,
    /// Stdout and stderr were genuinely separate streams.
    pub streams_separated: bool,
    /// Output was delivered while the command ran (vs. replayed after).
    pub live_streaming:    bool,
    pub stdout_capture:    CaptureStats,
    pub stderr_capture:    CaptureStats,
}

impl ExecStreamingResult {
    /// Wraps a buffered result with the honesty flags at their degraded
    /// defaults (`streams_separated: false`, `live_streaming: false`);
    /// providers set the flags they actually deliver. Capture stats
    /// start as fully-retained accounting of the wrapped buffers — a
    /// provider that truncated at the source overrides them — so
    /// `observed_bytes: 0` can never sit beside non-empty output.
    pub fn new(result: ExecResult) -> Self {
        let stdout_capture = CaptureStats::complete(result.stdout.len());
        let stderr_capture = CaptureStats::complete(result.stderr.len());
        Self {
            result,
            streams_separated: false,
            live_streaming: false,
            stdout_capture,
            stderr_capture,
        }
    }
}

/// Serializable spawn request for [`Exec::spawn_stdio`]. The program and
/// arguments run under the same contract as [`ExecSpec`]. `Debug` redacts
/// the arguments and env values, as on [`ExecSpec`].
#[derive(Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct SpawnSpec {
    pub program:     String,
    pub args:        Vec<String>,
    pub working_dir: Option<String>,
    pub env:         BTreeMap<String, String>,
}

impl fmt::Debug for SpawnSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SpawnSpec")
            .field("program", &self.program)
            .field("args", &"<redacted>")
            .field("working_dir", &self.working_dir)
            .field("env_keys", &self.env.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl SpawnSpec {
    /// A spec that spawns `program` with no arguments; add them with
    /// [`SpawnSpec::arg`] or [`SpawnSpec::args`].
    pub fn new(program: impl Into<String>) -> Self {
        Self {
            program:     program.into(),
            args:        Vec::new(),
            working_dir: None,
            env:         BTreeMap::new(),
        }
    }

    /// A spec that evaluates `script` as Bash source, under the same
    /// contract as [`ExecSpec::bash`].
    pub fn bash(script: impl Into<String>) -> Self {
        let mut spec = Self::new(BASH).args([BASH_COMMAND_FLAG, &script.into()]);
        spec.env.insert(BASH_ENV_VAR.to_owned(), String::new());
        spec
    }

    #[must_use]
    pub fn arg(mut self, arg: impl Into<String>) -> Self {
        self.args.push(arg.into());
        self
    }

    #[must_use]
    pub fn args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.args.extend(args.into_iter().map(Into::into));
        self
    }

    #[must_use]
    pub fn working_dir(mut self, dir: impl Into<String>) -> Self {
        self.working_dir = Some(dir.into());
        self
    }

    #[must_use]
    pub fn env_var(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.env.insert(key.into(), value.into());
        self
    }
}

/// A live bidirectional stdio process.
///
/// Stderr is not a stream: it is a bounded rolling tail intended for
/// diagnostics on unexpected exit.
///
/// There is no cancel token: the handle is the one lifecycle channel.
/// A caller with a `CancellationToken` wires it to
/// [`StdioProcessHandle::terminate`] itself:
///
/// ```ignore
/// tokio::select! {
///     () = token.cancelled() => process.handle.terminate().await,
///     outcome = process.handle.wait() => { /* natural exit */ }
/// }
/// ```
///
/// Dropping the handle does **not** stop the process — it runs to its
/// natural exit — so a caller that abandons the handle without
/// `terminate` leaks the workload.
pub struct StdioProcess {
    pub stdin:       Pin<Box<dyn AsyncWrite + Send>>,
    pub stdout:      Pin<Box<dyn AsyncRead + Send>>,
    pub stderr_tail: StderrTail,
    pub handle:      Box<dyn StdioProcessHandle>,
}

impl fmt::Debug for StdioProcess {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StdioProcess").finish_non_exhaustive()
    }
}

/// Control handle for a spawned stdio process.
#[async_trait]
pub trait StdioProcessHandle: Send + Sync {
    /// Requests termination (best-effort process-group kill).
    async fn terminate(&self);

    /// Waits for the process to end.
    async fn wait(&self) -> (Termination, Option<i32>);
}

const DEFAULT_STDERR_TAIL_BYTES: usize = 8 * 1024;

/// Bounded rolling tail of stderr output.
#[derive(Clone, Debug)]
pub struct StderrTail {
    inner: Arc<Mutex<TailBuffer>>,
}

#[derive(Debug)]
struct TailBuffer {
    max_bytes: usize,
    bytes:     Vec<u8>,
    truncated: bool,
}

impl StderrTail {
    pub fn new(max_bytes: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(TailBuffer {
                max_bytes,
                bytes: Vec::new(),
                truncated: false,
            })),
        }
    }

    /// Appends bytes, keeping only the newest `max_bytes`.
    pub fn push(&self, chunk: &[u8]) {
        let mut tail = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        tail.bytes.extend_from_slice(chunk);
        let max = tail.max_bytes;
        if tail.bytes.len() > max {
            let excess = tail.bytes.len() - max;
            tail.bytes.drain(..excess);
            tail.truncated = true;
        }
    }

    /// The retained tail decoded lossily, prefixed with an ellipsis when
    /// earlier output was dropped.
    pub fn to_string_lossy(&self) -> String {
        let tail = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        let text = String::from_utf8_lossy(&tail.bytes);
        if tail.truncated {
            format!("…{text}")
        } else {
            text.into_owned()
        }
    }
}

impl Default for StderrTail {
    fn default() -> Self {
        Self::new(DEFAULT_STDERR_TAIL_BYTES)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exec_spec_defaults_to_a_bounded_timeout() {
        let spec = ExecSpec::new("true");
        assert_eq!(spec.timeout, Some(ExecSpec::DEFAULT_TIMEOUT));
        assert_eq!(ExecSpec::new("true").no_timeout().timeout, None);
    }

    #[test]
    fn shell_status_decodes_the_signal_for_every_termination() {
        let duration = Duration::from_millis(1);
        for termination in [
            Termination::Exited,
            Termination::Cancelled,
            Termination::Killed,
            Termination::TimedOut,
        ] {
            let result = ExecResult::from_shell_status(termination, Some(143), duration);
            assert_eq!(result.signal, Some(15), "{termination:?}");
            assert_eq!(result.exit_code, Some(143), "the code stays intact");
            let result = ExecResult::from_shell_status(termination, Some(137), duration);
            assert_eq!(result.signal, Some(9), "{termination:?}");
        }
        // Ordinary codes, and no code at all, carry no signal.
        assert_eq!(
            ExecResult::from_shell_status(Termination::Exited, Some(7), duration).signal,
            None
        );
        assert_eq!(
            ExecResult::from_shell_status(Termination::Cancelled, None, duration).signal,
            None
        );
    }

    #[test]
    fn bash_helper_is_bash_dash_c_with_bash_env_blanked() {
        let spec = ExecSpec::bash("echo $HOME");
        assert_eq!(spec.program, "bash");
        assert_eq!(spec.args, ["-c", "echo $HOME"]);
        assert_eq!(spec.env.get("BASH_ENV").map(String::as_str), Some(""));

        let spawn = SpawnSpec::bash("cat");
        assert_eq!(spawn.program, "bash");
        assert_eq!(spawn.args, ["-c", "cat"]);
        assert_eq!(spawn.env.get("BASH_ENV").map(String::as_str), Some(""));
    }

    #[test]
    fn exec_and_spawn_spec_debug_redact_secrets() {
        let spec = ExecSpec::new("curl")
            .arg("https://user:hunter2@host/")
            .env_var("API_TOKEN", "hunter2")
            .stdin(b"hunter2".to_vec());
        let debug = format!("{spec:?}");
        assert!(!debug.contains("hunter2"), "debug: {debug}");
        assert!(debug.contains("curl"), "the program stays visible: {debug}");
        assert!(debug.contains("API_TOKEN"), "keys stay visible: {debug}");

        let spawn = SpawnSpec::new("run")
            .args(["--token", "hunter2"])
            .env_var("API_TOKEN", "hunter2");
        let debug = format!("{spawn:?}");
        assert!(!debug.contains("hunter2"), "debug: {debug}");
        assert!(debug.contains("API_TOKEN"), "keys stay visible: {debug}");
    }

    #[test]
    fn stderr_tail_keeps_only_newest_bytes() {
        let tail = StderrTail::new(8);
        tail.push(b"0123456789");
        assert_eq!(tail.to_string_lossy(), "…23456789");
        tail.push(b"AB");
        assert_eq!(tail.to_string_lossy(), "…456789AB");
    }

    #[test]
    fn capture_stats_truncated_is_additive_on_the_wire() {
        // A v1 payload without the field must decode, defaulting false.
        let old = r#"{"observed_bytes":3,"retained_bytes":3,"omitted_bytes":0}"#;
        let stats: CaptureStats = serde_json::from_str(old).expect("old shape decodes");
        assert!(!stats.truncated);
        assert!(!CaptureStats::complete(3).truncated);
    }

    #[test]
    fn exec_result_success_requires_clean_exit() {
        let ok = ExecResult::new(Termination::Exited, Some(0), Duration::from_millis(1));
        assert!(ok.success());
        let cancelled = ExecResult::new(Termination::Cancelled, Some(0), Duration::from_millis(1));
        assert!(!cancelled.success());
    }
}
