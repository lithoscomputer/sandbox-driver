//! Execute Docker CLI commands through Daytona's native process APIs.
//! Output is encoded by a command-local subprocess wrapper because the SDK's
//! session log decoder otherwise replaces non-UTF-8 bytes.

use std::fmt::Write as _;
use std::future::pending;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use std::{io, iter, mem};

use async_trait::async_trait;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use sandbox_driver::{
    BASH_ENV_VAR, Capability, Error, Exec, ExecControls, ExecResult, ExecSpec, ExecStreamingResult,
    OutputCaptureBuffer, OutputSanitization, OutputSanitizer, OutputSink, OutputStream, Pty,
    PtyOptions, PtySession, PtySize, Result, SpawnSpec, StdioProcess, StdioProcessHandle,
    StopLevel, Termination, stop_signal,
};
use sandbox_driver_docker::DockerExec;
use tokio::runtime::Handle;
use tokio::sync::Mutex;
use tokio::time;
use tokio_util::sync::CancellationToken;

use crate::nested_docker::{CONTAINER_NAME, DockerCli};
use crate::{exec_line, shell_quote};

const STOP_TIMEOUT: Duration = Duration::from_secs(10);
const TERM_GRACE: Duration = Duration::from_secs(2);
const DRAIN_GRACE: Duration = Duration::from_secs(10);
const MAX_FRAME_BYTES: usize = 32 * 1024;

// One process and its two pipes, with no socket or listener. Every record is
// ASCII; the final process status remains the command's status. Selectors keep
// both pipes drained without buffering an entire command in the VM.
const ENCODE_OUTPUT: &str = r"
import base64, json, os, selectors, subprocess, sys
argv, has_stdin = json.loads(sys.argv[1])
child = subprocess.Popen(argv, stdin=sys.stdin.buffer if has_stdin else subprocess.DEVNULL,
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE)
selector = selectors.DefaultSelector()
selector.register(child.stdout, selectors.EVENT_READ, 'O')
selector.register(child.stderr, selectors.EVENT_READ, 'E')
while selector.get_map():
    for key, _ in selector.select():
        data = os.read(key.fileobj.fileno(), 16384)
        if not data:
            selector.unregister(key.fileobj)
            key.fileobj.close()
            continue
        sys.stdout.write(key.data + base64.b64encode(data).decode('ascii') + '\n')
        sys.stdout.flush()
code = child.wait()
sys.exit(code if code >= 0 else 128 - code)
";

fn encoded_spec(spec: &ExecSpec) -> Result<ExecSpec> {
    let argv: Vec<_> = iter::once(&spec.program).chain(&spec.args).collect();
    let payload = serde_json::to_string(&(argv, spec.stdin.is_some()))
        .map_err(|error| Error::io("encoding Docker command", io::Error::other(error)))?;
    let mut encoded = ExecSpec::new("python3").args(["-u", "-c", ENCODE_OUTPUT, &payload]);
    encoded.timeout = spec.timeout;
    encoded.working_dir.clone_from(&spec.working_dir);
    encoded.env.clone_from(&spec.env);
    encoded.stdin.clone_from(&spec.stdin);
    Ok(encoded)
}

struct FramedOutput {
    pending: Vec<u8>,
    streams: [(OutputSanitizer, OutputCaptureBuffer); 2],
    sink:    Option<OutputSink>,
}

impl FramedOutput {
    fn new(policy: OutputSanitization, controls: &ExecControls) -> Self {
        Self {
            pending: Vec::new(),
            streams: [0, 1].map(|_| {
                (
                    OutputSanitizer::new(policy),
                    OutputCaptureBuffer::new(controls.retained_output_limit),
                )
            }),
            sink:    controls.sink.clone(),
        }
    }

    async fn emit(&mut self, index: usize, raw: &[u8]) -> Result<()> {
        let (sanitizer, capture) = &mut self.streams[index];
        let bytes = sanitizer.push(raw);
        capture.push(&bytes);
        if !bytes.is_empty() {
            if let Some(sink) = &self.sink {
                let stream = [OutputStream::Stdout, OutputStream::Stderr][index];
                sink(stream, bytes).await?;
            }
        }
        Ok(())
    }

    async fn push(&mut self, stream: OutputStream, mut bytes: &[u8]) -> Result<()> {
        if stream == OutputStream::Stderr {
            // Python startup failures remain ordinary stderr diagnostics.
            return self.emit(1, bytes).await;
        }
        while !bytes.is_empty() {
            let end = bytes.iter().position(|byte| *byte == b'\n');
            let take = end.map_or(bytes.len(), |end| end + 1);
            if self.pending.len() + take > MAX_FRAME_BYTES {
                return Err(Error::io(
                    "decoding Docker output",
                    io::Error::new(io::ErrorKind::InvalidData, "output frame is too large"),
                ));
            }
            self.pending.extend_from_slice(&bytes[..take]);
            bytes = &bytes[take..];
            if end.is_some() {
                let index = match self.pending.first() {
                    Some(b'O') => 0,
                    Some(b'E') => 1,
                    _ => {
                        return Err(Error::io(
                            "decoding Docker output",
                            io::Error::new(io::ErrorKind::InvalidData, "invalid output frame"),
                        ));
                    }
                };
                let raw = STANDARD
                    .decode(&self.pending[1..self.pending.len() - 1])
                    .map_err(|error| {
                        Error::io("decoding Docker output", io::Error::other(error))
                    })?;
                self.pending.clear();
                self.emit(index, &raw).await?;
            }
        }
        Ok(())
    }

    async fn finish(&mut self, mut result: ExecStreamingResult) -> Result<ExecStreamingResult> {
        for (index, (sanitizer, capture)) in self.streams.iter_mut().enumerate() {
            let final_bytes = sanitizer.finish();
            capture.push(&final_bytes);
            if !final_bytes.is_empty() {
                if let Some(sink) = &self.sink {
                    sink(
                        [OutputStream::Stdout, OutputStream::Stderr][index],
                        final_bytes,
                    )
                    .await?;
                }
            }
        }
        result.result.stdout = self.streams[0].1.to_bytes();
        result.result.stderr = self.streams[1].1.to_bytes();
        let truncated = result.stdout_capture.truncated
            || result.stderr_capture.truncated
            || !self.pending.is_empty();
        result.stdout_capture = self.streams[0].1.stats();
        result.stderr_capture = self.streams[1].1.stats();
        result.stdout_capture.truncated |= truncated;
        result.stderr_capture.truncated |= truncated;
        result.streams_separated = true;
        Ok(result)
    }
}

/// Runs an arbitrary Docker CLI invocation while preserving exact output.
/// The caller owns container-level stop handling; native stop tokens here
/// control only the VM command that transports its output.
pub(super) async fn run_cli(
    cli: &DockerCli,
    spec: &ExecSpec,
    controls: ExecControls,
) -> Result<ExecStreamingResult> {
    if controls.stdin.is_some() {
        return Err(Error::unsupported(Capability::ExecStdinStream));
    }
    let output = Arc::new(Mutex::new(FramedOutput::new(
        spec.output_sanitization,
        &controls,
    )));
    let sink: OutputSink = Arc::new({
        let output = Arc::clone(&output);
        move |stream, bytes| {
            let output = Arc::clone(&output);
            Box::pin(async move { output.lock().await.push(stream, &bytes).await })
        }
    });
    let encoded = encoded_spec(spec)?;
    let result = cli
        .exec
        .run_streaming(&encoded, ExecControls {
            term: controls.term,
            kill: controls.kill,
            sink: Some(sink),
            retained_output_limit: Some(0),
            ..ExecControls::default()
        })
        .await?;
    output.lock().await.finish(result).await
}

/// One inner process group. Native session deletion stops the Docker client;
/// this second command tells the existing in-container watcher to stop the job.
struct Job {
    cli:       Arc<DockerCli>,
    stop_file: String,
    pid_file:  String,
    finished:  AtomicBool,
}

impl Job {
    fn new(cli: Arc<DockerCli>) -> Self {
        let nonce: u128 = rand::random();
        let prefix = format!("/tmp/.sandbox-driver/daytona-{nonce:032x}");
        Self {
            cli,
            stop_file: format!("{prefix}.stop"),
            pid_file: format!("{prefix}.pid"),
            finished: AtomicBool::new(false),
        }
    }

    fn command(&self, spec: &ExecSpec) -> ExecSpec {
        let mut args = vec!["exec".to_owned(), "-i".to_owned(), "--workdir".to_owned()];
        args.push(self.cli.resolve(spec.working_dir.as_deref().unwrap_or(".")));
        args.extend(["--env".to_owned(), format!("{BASH_ENV_VAR}=")]);
        args.push(CONTAINER_NAME.to_owned());
        args.extend([
            "/bin/sh".to_owned(),
            "-c".to_owned(),
            DockerExec::command_wrapper(&self.stop_file, &self.pid_file, spec.stdin.is_some()),
            "sandbox-driver".to_owned(),
        ]);
        args.extend(spec.env.iter().map(|(key, value)| format!("{key}={value}")));
        args.push(spec.program.clone());
        args.extend(spec.args.iter().cloned());
        let mut command = DockerCli::command(args).no_timeout();
        command.stdin.clone_from(&spec.stdin);
        command.output_sanitization = spec.output_sanitization;
        command
    }

    async fn stop(&self, mode: StopLevel) -> Result<()> {
        if self.finished.load(Ordering::Acquire) {
            return Ok(());
        }
        stop_job(&self.cli, &self.stop_file, mode).await
    }
}

async fn stop_job(cli: &DockerCli, stop_file: &str, mode: StopLevel) -> Result<()> {
    let script = stop_script(stop_file, mode);
    let spec = DockerCli::command(vec![
        "exec".to_owned(),
        "--workdir".to_owned(),
        "/".to_owned(),
        "--env".to_owned(),
        format!("{BASH_ENV_VAR}="),
        CONTAINER_NAME.to_owned(),
        "/bin/sh".to_owned(),
        "-c".to_owned(),
        script,
    ]);
    time::timeout(STOP_TIMEOUT, cli.run_spec(&spec))
        .await
        .map_err(|_| {
            Error::io(
                "stopping nested job",
                io::Error::other("stop request timed out"),
            )
        })??;
    Ok(())
}

fn stop_script(stop_file: &str, mode: StopLevel) -> String {
    let mode = match mode {
        StopLevel::Term => "term",
        StopLevel::Kill => "kill",
    };
    let request = format!("{stop_file}.request-{:032x}", rand::random::<u128>());
    // A cancelled TERM RPC can still finish after Drop sent KILL. Publish a
    // complete mode atomically; TERM only creates and can never replace KILL.
    format!(
        "request={}; stop_file={}; mkdir -p \"${{stop_file%/*}}\" || exit; \
         trap 'rm -f \"$request\"' EXIT; printf '%s' {} > \"$request\" || exit; \
         if [ {} = kill ]; then mv -f \"$request\" \"$stop_file\"; \
         else ln \"$request\" \"$stop_file\" 2>/dev/null || [ -e \"$stop_file\" ]; fi",
        shell_quote(&request),
        shell_quote(stop_file),
        shell_quote(mode),
        shell_quote(mode)
    )
}

impl Drop for Job {
    fn drop(&mut self) {
        if self.finished.load(Ordering::Acquire) {
            return;
        }
        if let Ok(runtime) = Handle::try_current() {
            let cli = Arc::clone(&self.cli);
            let stop_file = self.stop_file.clone();
            runtime.spawn(async move {
                if let Err(error) = stop_job(&cli, &stop_file, StopLevel::Kill).await {
                    tracing::warn!(error = %error, "abandoned nested job stop failed");
                }
            });
        }
    }
}

pub(super) struct NestedExec {
    cli: Arc<DockerCli>,
}

impl NestedExec {
    pub(super) fn new(cli: Arc<DockerCli>) -> Self {
        Self { cli }
    }
}

#[async_trait]
impl Exec for NestedExec {
    async fn run(&self, spec: &ExecSpec) -> Result<ExecResult> {
        Ok(self
            .run_streaming(spec, ExecControls::default())
            .await?
            .result)
    }

    async fn run_streaming(
        &self,
        spec: &ExecSpec,
        controls: ExecControls,
    ) -> Result<ExecStreamingResult> {
        if controls.stdin.is_some() {
            return Err(Error::unsupported(Capability::ExecStdinStream));
        }
        let stopped = if controls
            .kill
            .as_ref()
            .is_some_and(CancellationToken::is_cancelled)
        {
            Some(Termination::Killed)
        } else if controls
            .term
            .as_ref()
            .is_some_and(CancellationToken::is_cancelled)
        {
            Some(Termination::Cancelled)
        } else if spec.timeout == Some(Duration::ZERO) {
            Some(Termination::TimedOut)
        } else {
            None
        };
        if let Some(termination) = stopped {
            return Ok(ExecStreamingResult::new(ExecResult::new(
                termination,
                None,
                Duration::ZERO,
            )));
        }
        let job = Job::new(Arc::clone(&self.cli));
        let command = job.command(spec);
        let sink_failed = CancellationToken::new();
        let sink = controls.sink.as_ref().map(|sink| {
            let sink = Arc::clone(sink);
            let failed = sink_failed.clone();
            let sink: OutputSink = Arc::new(move |stream, bytes| {
                let sink = Arc::clone(&sink);
                let failed = failed.clone();
                Box::pin(async move {
                    let result = sink(stream, bytes).await;
                    if result.is_err() {
                        failed.cancel();
                    }
                    result
                })
            });
            sink
        });
        let transport_kill = CancellationToken::new();
        let run = run_cli(&self.cli, &command, ExecControls {
            sink,
            kill: Some(transport_kill.clone()),
            retained_output_limit: controls.retained_output_limit,
            ..ExecControls::default()
        });
        tokio::pin!(run);
        let deadline = async {
            match spec.timeout {
                Some(duration) => time::sleep(duration).await,
                None => pending().await,
            }
        };
        tokio::pin!(deadline);
        let mut termination = Termination::Exited;
        let mut hard_stop = false;
        let mut drain_deadline = None;
        let mut transport_stopped = false;
        loop {
            tokio::select! {
                result = &mut run => {
                    let mut result = result?;
                    if (result.result.termination != Termination::Exited || sink_failed.is_cancelled()) && !hard_stop {
                        job.stop(StopLevel::Kill).await?;
                    }
                    if sink_failed.is_cancelled() && termination == Termination::Exited {
                        termination = Termination::Cancelled;
                    }
                    job.finished.store(true, Ordering::Release);
                    if termination != Termination::Exited {
                        result.result.termination = termination;
                    }
                    return Ok(result);
                }
                () = stop_signal(controls.kill.as_ref()), if !hard_stop => {
                    job.stop(StopLevel::Kill).await?;
                    termination = Termination::Killed;
                    hard_stop = true;
                    drain_deadline = Some(time::Instant::now() + DRAIN_GRACE);
                }
                () = stop_signal(controls.term.as_ref()), if termination == Termination::Exited => {
                    job.stop(StopLevel::Term).await?;
                    termination = Termination::Cancelled;
                }
                () = &mut deadline, if !hard_stop => {
                    job.stop(StopLevel::Kill).await?;
                    termination = Termination::TimedOut;
                    hard_stop = true;
                    drain_deadline = Some(time::Instant::now() + DRAIN_GRACE);
                }
                () = sink_failed.cancelled(), if !hard_stop => {
                    job.stop(StopLevel::Kill).await?;
                    termination = Termination::Cancelled;
                    hard_stop = true;
                    drain_deadline = Some(time::Instant::now() + DRAIN_GRACE);
                }
                () = async {
                    match drain_deadline {
                        Some(deadline) => time::sleep_until(deadline).await,
                        None => pending().await,
                    }
                } => {
                    if transport_stopped {
                        return Err(Error::io("draining nested job output", io::Error::other("output did not close after the job was killed")));
                    }
                    transport_kill.cancel();
                    transport_stopped = true;
                    drain_deadline = Some(time::Instant::now() + STOP_TIMEOUT * 3);
                }
            }
        }
    }

    async fn spawn_stdio(&self, spec: &SpawnSpec) -> Result<StdioProcess> {
        let job = Job::new(Arc::clone(&self.cli));
        let mut command = ExecSpec::new(&spec.program).args(spec.args.clone());
        command.env.clone_from(&spec.env);
        command.working_dir.clone_from(&spec.working_dir);
        // The wrapper must preserve the interactive stdin descriptor.
        command.stdin = Some(Vec::new());
        let command = job.command(&command);
        let mut spawn = SpawnSpec::new(command.program).args(command.args);
        spawn.env = command.env;
        spawn.working_dir = command.working_dir;
        let mut process = self.cli.exec.spawn_stdio(&spawn).await?;
        process.handle = Box::new(NestedStdioHandle {
            inner: process.handle,
            job,
        });
        Ok(process)
    }
}

struct NestedStdioHandle {
    inner: Box<dyn StdioProcessHandle>,
    job:   Job,
}

#[async_trait]
impl StdioProcessHandle for NestedStdioHandle {
    async fn terminate(&self) {
        if let Err(error) = self.job.stop(StopLevel::Term).await {
            tracing::warn!(error = %error, "nested stdio TERM failed");
        }
        let stopped = if matches!(
            time::timeout(TERM_GRACE, self.inner.wait()).await,
            Ok((Termination::Exited, _))
        ) {
            true
        } else {
            match self.job.stop(StopLevel::Kill).await {
                Ok(()) => true,
                Err(error) => {
                    tracing::warn!(error = %error, "nested stdio KILL failed");
                    false
                }
            }
        };
        self.inner.terminate().await;
        self.job.finished.store(stopped, Ordering::Release);
    }

    async fn wait(&self) -> (Termination, Option<i32>) {
        let result = self.inner.wait().await;
        if result.0 != Termination::Exited {
            if let Err(error) = self.job.stop(StopLevel::Kill).await {
                tracing::warn!(error = %error, "nested stdio stop after transport failure failed");
                return (Termination::Unknown, None);
            }
        }
        self.job.finished.store(true, Ordering::Release);
        result
    }
}

#[async_trait]
impl Pty for NestedExec {
    async fn open(&self, options: &PtyOptions) -> Result<Box<dyn PtySession>> {
        let nonce: u128 = rand::random();
        let nonce = format!("{nonce:032x}");
        let pid_file = format!("/tmp/.sandbox-driver/pty-{nonce}.pid");
        let mut environment = options.env.clone();
        environment
            .entry("TERM".to_owned())
            .or_insert_with(|| "xterm-256color".to_owned());
        environment
            .entry("LANG".to_owned())
            .or_insert_with(|| "C.UTF-8".to_owned());
        environment.insert(BASH_ENV_VAR.to_owned(), String::new());
        let mut native_options = PtyOptions::default();
        native_options.size = options.size;
        native_options.working_dir = Some("/".to_owned());
        let command = DockerCli::command(vec![
            "exec".to_owned(),
            "-it".to_owned(),
            "--workdir".to_owned(),
            self.cli
                .resolve(options.working_dir.as_deref().unwrap_or(".")),
        ]);
        let mut bootstrap = exec_line(&command.env, &command.program, &command.args);
        // The PTY echoes its bootstrap before stty can disable echo. Forward
        // values through private environment names, so echoed source contains
        // only keys and references, including for Docker's own environment.
        for (index, (key, value)) in environment.into_iter().enumerate() {
            let alias = format!("SANDBOX_DRIVER_PTY_ENV_{index}");
            native_options.env.insert(alias.clone(), value);
            write!(
                bootstrap,
                " --env {}\"${alias}\"",
                shell_quote(&format!("{key}="))
            )
            .expect("writing a String cannot fail");
        }
        let terminal = format!(
            "mkdir -p /tmp/.sandbox-driver; printf '%s' $$ > {}; \
             printf '\\n%s%s\\n' sandbox-driver-ready- {}; exec sh -l",
            shell_quote(&pid_file),
            shell_quote(&nonce)
        );
        for arg in [CONTAINER_NAME, "/bin/sh", "-c", &terminal] {
            bootstrap.push(' ');
            bootstrap.push_str(&shell_quote(arg));
        }
        let native: Arc<dyn PtySession> = Arc::from(self.cli.pty.open(&native_options).await?);
        let session = NestedPtySession {
            cli: Arc::clone(&self.cli),
            native,
            pid_file,
            pending: Mutex::new(Vec::new()),
            closed: AtomicBool::new(false),
        };
        session
            .native
            .write_input(format!("stty -echo; {bootstrap}\n").as_bytes())
            .await?;
        let marker = format!("sandbox-driver-ready-{nonce}").into_bytes();
        let ready = async {
            let mut output = Vec::new();
            while let Some(bytes) = session.native.read_output().await? {
                output.extend(bytes);
                if let Some(index) = output
                    .windows(marker.len())
                    .position(|window| window == marker)
                {
                    session
                        .pending
                        .lock()
                        .await
                        .extend_from_slice(&output[index + marker.len()..]);
                    return Ok(());
                }
                // Keep only the suffix needed to match a split marker.
                if output.len() > marker.len() {
                    output.drain(..output.len() - marker.len());
                }
            }
            Err(Error::io(
                "starting nested terminal",
                io::Error::other("terminal ended before startup"),
            ))
        };
        match time::timeout(Duration::from_secs(30), ready).await {
            Ok(Ok(())) => Ok(Box::new(session)),
            result => {
                let _ = session.close().await;
                match result {
                    Ok(Err(error)) => Err(error),
                    Err(_) => Err(Error::io(
                        "starting nested terminal",
                        io::Error::other("terminal startup timed out"),
                    )),
                    Ok(Ok(())) => unreachable!("successful startup returned above"),
                }
            }
        }
    }
}

struct NestedPtySession {
    cli:      Arc<DockerCli>,
    native:   Arc<dyn PtySession>,
    pid_file: String,
    pending:  Mutex<Vec<u8>>,
    closed:   AtomicBool,
}

async fn close_terminal(cli: &DockerCli, pid_file: &str) -> Result<()> {
    let pid_file = shell_quote(pid_file);
    let command = format!(
        "if [ -f {pid_file} ]; then pid=$(cat {pid_file}); rm -f {pid_file}; \
         case \"$pid\" in ''|*[!0-9]*) : ;; *) \
         kill -TERM \"-$pid\" 2>/dev/null || kill -TERM \"$pid\" 2>/dev/null || true; \
         for _ in 1 2 3 4 5; do kill -0 \"$pid\" 2>/dev/null || break; sleep 0.2; done; \
         if kill -0 \"$pid\" 2>/dev/null; then kill -KILL \"-$pid\" 2>/dev/null || true; \
         kill -KILL \"$pid\" 2>/dev/null || true; fi ;; esac; fi"
    );
    let spec = DockerCli::command(vec![
        "exec".to_owned(),
        "--user".to_owned(),
        "0".to_owned(),
        "--workdir".to_owned(),
        "/".to_owned(),
        CONTAINER_NAME.to_owned(),
        "/bin/sh".to_owned(),
        "-c".to_owned(),
        command,
    ])
    .timeout(STOP_TIMEOUT);
    time::timeout(STOP_TIMEOUT, cli.run_spec(&spec))
        .await
        .map_err(|_| {
            Error::io(
                "closing nested terminal",
                io::Error::other("terminal stop timed out"),
            )
        })??;
    Ok(())
}

#[async_trait]
impl PtySession for NestedPtySession {
    async fn write_input(&self, bytes: &[u8]) -> Result<()> {
        self.native.write_input(bytes).await
    }

    async fn read_output(&self) -> Result<Option<Vec<u8>>> {
        let mut pending = self.pending.lock().await;
        if !pending.is_empty() {
            return Ok(Some(mem::take(&mut *pending)));
        }
        drop(pending);
        self.native.read_output().await
    }

    async fn resize(&self, size: PtySize) -> Result<()> {
        self.native.resize(size).await
    }

    async fn close(&self) -> Result<()> {
        if self.closed.load(Ordering::Acquire) {
            return Ok(());
        }
        let stopped = close_terminal(&self.cli, &self.pid_file).await;
        let closed = self.native.close().await;
        self.closed.store(true, Ordering::Release);
        stopped.and(closed)
    }
}

impl Drop for NestedPtySession {
    fn drop(&mut self) {
        if self.closed.load(Ordering::Acquire) {
            return;
        }
        if let Ok(runtime) = Handle::try_current() {
            let cli = Arc::clone(&self.cli);
            let native = Arc::clone(&self.native);
            let pid_file = self.pid_file.clone();
            runtime.spawn(async move {
                let _ = close_terminal(&cli, &pid_file).await;
                let _ = native.close().await;
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;
    use std::process::{Command, Stdio};
    use std::{env, fs};

    use tokio::task::spawn_blocking;

    use super::*;

    #[test]
    fn a_late_term_request_cannot_downgrade_a_kill() {
        let dir = env::temp_dir().join(format!("sandbox-stop-{:032x}", rand::random::<u128>()));
        fs::create_dir(&dir).expect("control directory");
        let stop_file = dir.join("job.stop");
        for mode in [StopLevel::Term, StopLevel::Kill, StopLevel::Term] {
            assert!(
                Command::new("/bin/sh")
                    .args([
                        "-c",
                        &stop_script(stop_file.to_str().expect("control path"), mode)
                    ])
                    .status()
                    .expect("stop request command")
                    .success()
            );
        }
        assert_eq!(
            fs::read_to_string(&stop_file).expect("published mode"),
            "kill"
        );
        assert_eq!(fs::read_dir(&dir).expect("control files").count(), 1);
        fs::remove_dir_all(dir).expect("remove test control directory");
    }

    #[tokio::test]
    async fn fragmented_native_frames_preserve_binary_streams_and_retention() {
        let spec = ExecSpec::new("python3").args([
            "-c",
            "import os; os.write(1, bytes([0,255,128,10,65])); os.write(2, bytes([254,0,66]))",
        ]);
        let encoded = encoded_spec(&spec).expect("encoded command");
        let output = spawn_blocking(move || {
            Command::new(encoded.program)
                .args(encoded.args)
                .output()
                .expect("Python command wrapper")
        })
        .await
        .expect("command joined");
        assert!(output.status.success(), "{:?}", output.stderr);
        let observed = Arc::new(Mutex::new([Vec::new(), Vec::new()]));
        let sink: OutputSink = Arc::new({
            let observed = Arc::clone(&observed);
            move |stream, bytes| {
                let observed = Arc::clone(&observed);
                Box::pin(async move {
                    let index = usize::from(stream == OutputStream::Stderr);
                    observed.lock().await[index].extend(bytes);
                    Ok(())
                })
            }
        });
        let mut framed = FramedOutput::new(OutputSanitization::Raw, &ExecControls {
            sink: Some(sink),
            retained_output_limit: Some(2),
            ..ExecControls::default()
        });
        for fragment in output.stdout.chunks(3) {
            framed
                .push(OutputStream::Stdout, fragment)
                .await
                .expect("fragment decoded");
        }
        let mut native = ExecStreamingResult::new(ExecResult::new(
            Termination::Exited,
            Some(0),
            Duration::ZERO,
        ));
        // The transport retained no encoded bytes; all were delivered to the
        // decoder. Deliberate transport omission is not decoded truncation.
        native.stdout_capture.observed_bytes = output.stdout.len();
        native.stdout_capture.omitted_bytes = output.stdout.len();
        let result = framed.finish(native).await.expect("capture completed");
        assert_eq!(*observed.lock().await, [vec![0, 255, 128, 10, 65], vec![
            254, 0, 66
        ]]);
        assert_eq!(result.result.stdout, [0, 65]);
        assert_eq!(result.result.stderr, [254, 66]);
        assert_eq!(result.stdout_capture.observed_bytes, 5);
        assert_eq!(result.stdout_capture.retained_bytes, 2);
        assert_eq!(result.stdout_capture.omitted_bytes, 3);
        assert!(!result.stdout_capture.truncated);
        assert!(!result.stderr_capture.truncated);
        assert!(result.streams_separated);
    }

    #[tokio::test]
    async fn fixed_binary_stdin_reaches_the_command_and_closes_for_eof() {
        let spec = ExecSpec::new("cat").stdin(vec![0, 255, 128, 10]);
        let encoded = encoded_spec(&spec).expect("encoded command");
        let output = spawn_blocking(move || {
            let mut child = Command::new(encoded.program)
                .args(encoded.args)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .expect("command wrapper");
            child
                .stdin
                .take()
                .expect("stdin pipe")
                .write_all(encoded.stdin.as_deref().expect("fixed input"))
                .expect("stdin delivered");
            child.wait_with_output().expect("command observed EOF")
        })
        .await
        .expect("command joined");
        assert!(output.status.success());
        let mut framed = FramedOutput::new(OutputSanitization::Raw, &ExecControls::default());
        framed
            .push(OutputStream::Stdout, &output.stdout)
            .await
            .expect("output decoded");
        let result = framed
            .finish(ExecStreamingResult::new(ExecResult::new(
                Termination::Exited,
                output.status.code(),
                Duration::ZERO,
            )))
            .await
            .expect("capture completed");
        assert_eq!(result.result.stdout, spec.stdin.expect("fixed input"));
    }

    #[tokio::test]
    async fn incomplete_frames_report_loss_and_oversized_frames_are_bounded() {
        let mut framed = FramedOutput::new(OutputSanitization::Raw, &ExecControls::default());
        framed
            .push(OutputStream::Stdout, b"Ow")
            .await
            .expect("partial frame");
        let result = framed
            .finish(ExecStreamingResult::new(ExecResult::new(
                Termination::Exited,
                Some(0),
                Duration::ZERO,
            )))
            .await
            .expect("partial capture reports loss");
        assert!(result.stdout_capture.truncated);
        assert!(
            framed
                .push(OutputStream::Stdout, &vec![b'A'; MAX_FRAME_BYTES])
                .await
                .is_err()
        );
    }
}
