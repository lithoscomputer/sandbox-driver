use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, PoisonError};
use std::time::Duration;

use async_trait::async_trait;
use sandbox_driver::{
    BASH_PROBE_SCRIPT, CaptureStats, Error, Exec, ExecControls, ExecResult, ExecSpec,
    ExecStreamingResult, OutputCaptureBuffer, OutputStream, Result, SpawnSpec, StderrTail,
    StdioProcess, StdioProcessHandle, Termination, TransportError,
};
use tokio::io::{AsyncReadExt, DuplexStream, duplex};
use tokio::time::sleep;

/// What a scripted command answers with.
enum Outcome {
    Result(ExecResult),
    /// The command never ran: a transport failure with this message.
    Failure(String),
}

/// A test's own answer for a command, consulted before the queue.
type Responder = Box<dyn Fn(&ExecSpec) -> Option<ExecResult> + Send + Sync>;

/// An [`Exec`] that answers commands from a script.
///
/// A responder set with [`ScriptedExec::respond_with`] answers first, by
/// looking at the spec; otherwise results are consumed in order from a
/// queue; when the queue is empty the default result answers (exit 0, no
/// output, unless replaced with [`ScriptedExec::set_default`]). Every spec
/// is recorded for assertions.
/// The bash probe that `activate` runs is answered on the side — passing
/// unless [`ScriptedExec::fail_probe`] was set — and is neither queued
/// nor recorded, so a test's expectations about the commands it drove
/// are not disturbed by activation.
pub struct ScriptedExec {
    responder:         Mutex<Option<Responder>>,
    outcomes:          Mutex<VecDeque<Outcome>>,
    default:           Mutex<Outcome>,
    recorded:          Mutex<Vec<ExecSpec>>,
    term_stops:        Mutex<Vec<bool>>,
    stdin:             Mutex<Vec<Vec<u8>>>,
    probe_fails:       AtomicBool,
    streams_separated: AtomicBool,
    stdio:             Mutex<Option<ScriptedStdioProcess>>,
    stdio_error:       Mutex<Option<String>>,
}

impl Default for ScriptedExec {
    fn default() -> Self {
        Self::new()
    }
}

impl ScriptedExec {
    pub fn new() -> Self {
        Self {
            responder:         Mutex::new(None),
            outcomes:          Mutex::new(VecDeque::new()),
            default:           Mutex::new(Outcome::Result(Self::ok(""))),
            recorded:          Mutex::new(Vec::new()),
            term_stops:        Mutex::new(Vec::new()),
            stdin:             Mutex::new(Vec::new()),
            probe_fails:       AtomicBool::new(false),
            streams_separated: AtomicBool::new(true),
            stdio:             Mutex::new(None),
            stdio_error:       Mutex::new(None),
        }
    }

    /// A successful result with the given stdout.
    pub fn ok(stdout: &str) -> ExecResult {
        let mut result = ExecResult::new(Termination::Exited, Some(0), Duration::from_millis(1));
        result.stdout = stdout.as_bytes().to_vec();
        result
    }

    /// A clean exit with a non-zero code and the given stderr.
    pub fn failed(code: i32, stderr: &str) -> ExecResult {
        let mut result = ExecResult::new(Termination::Exited, Some(code), Duration::from_millis(1));
        result.stderr = stderr.as_bytes().to_vec();
        result
    }

    /// Queues a result for the next command.
    pub fn push_result(&self, result: ExecResult) -> &Self {
        self.outcomes
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push_back(Outcome::Result(result));
        self
    }

    /// Queues a transport failure for the next command: it never runs and
    /// the caller sees an [`Error::Transport`] with this message.
    pub fn push_failure(&self, message: impl Into<String>) -> &Self {
        self.outcomes
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push_back(Outcome::Failure(message.into()));
        self
    }

    /// Answers commands by looking at their spec: a responder that returns
    /// `Some` decides the result, `None` falls through to the queue and the
    /// default. For tests that interleave different commands and want each
    /// answered by what it is rather than by its position.
    pub fn respond_with(
        &self,
        responder: impl Fn(&ExecSpec) -> Option<ExecResult> + Send + Sync + 'static,
    ) -> &Self {
        *self
            .responder
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(Box::new(responder));
        self
    }

    /// Replaces the result that answers when the queue is empty.
    pub fn set_default(&self, result: ExecResult) -> &Self {
        *self.default.lock().unwrap_or_else(PoisonError::into_inner) = Outcome::Result(result);
        self
    }

    /// Makes every command the queue does not answer fail as a transport
    /// failure with this message: the sandbox is unreachable.
    pub fn fail_by_default(&self, message: impl Into<String>) -> &Self {
        *self.default.lock().unwrap_or_else(PoisonError::into_inner) =
            Outcome::Failure(message.into());
        self
    }

    /// Makes the bash probe fail, so `activate` reports an unusable
    /// sandbox.
    pub fn fail_probe(&self, fail: bool) -> &Self {
        self.probe_fails.store(fail, Ordering::SeqCst);
        self
    }

    /// Whether streaming results report separated streams (the default)
    /// or a provider that merges them.
    pub fn set_streams_separated(&self, separated: bool) -> &Self {
        self.streams_separated.store(separated, Ordering::SeqCst);
        self
    }

    /// The process the next [`Exec::spawn_stdio`] returns.
    pub fn set_stdio_process(&self, process: ScriptedStdioProcess) -> &Self {
        *self.stdio.lock().unwrap_or_else(PoisonError::into_inner) = Some(process);
        self
    }

    /// Makes [`Exec::spawn_stdio`] fail with a transport error.
    pub fn set_stdio_error(&self, message: impl Into<String>) -> &Self {
        *self
            .stdio_error
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(message.into());
        self
    }

    /// Every spec run so far, in order, probes excluded.
    pub fn recorded(&self) -> Vec<ExecSpec> {
        self.recorded
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// The recorded specs rendered one per line: a Bash spec as its
    /// script, any other as its program followed by its arguments.
    pub fn commands(&self) -> Vec<String> {
        self.recorded().iter().map(render).collect()
    }

    /// Whether each streaming command was given a `term` stop, in order,
    /// probes excluded. For tests that assert a cancellation reaches the
    /// provider.
    pub fn term_stops(&self) -> Vec<bool> {
        self.term_stops
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// The standard input each streaming command was fed, in order.
    pub fn captured_stdin(&self) -> Vec<Vec<u8>> {
        self.stdin
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    fn is_probe(spec: &ExecSpec) -> bool {
        spec.args.iter().any(|arg| arg == BASH_PROBE_SCRIPT)
    }

    fn answer(&self, spec: &ExecSpec) -> Result<ExecResult> {
        if Self::is_probe(spec) {
            return Ok(if self.probe_fails.load(Ordering::SeqCst) {
                Self::failed(1, "probe: scripted failure")
            } else {
                Self::ok("fabro-bash-ready")
            });
        }
        self.recorded
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(spec.clone());
        if let Some(result) = self
            .responder
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            .and_then(|responder| responder(spec))
        {
            return Ok(result);
        }
        let next = self
            .outcomes
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .pop_front();
        let outcome = match next {
            Some(outcome) => outcome,
            None => match &*self.default.lock().unwrap_or_else(PoisonError::into_inner) {
                Outcome::Result(result) => Outcome::Result(result.clone()),
                Outcome::Failure(message) => Outcome::Failure(message.clone()),
            },
        };
        match outcome {
            Outcome::Result(result) => Ok(result),
            Outcome::Failure(message) => Err(Error::Transport(TransportError::new(message))),
        }
    }
}

fn render(spec: &ExecSpec) -> String {
    match (spec.program.as_str(), spec.args.as_slice()) {
        ("bash", [flag, script]) if flag == "-c" => script.clone(),
        (program, args) => {
            let mut rendered = program.to_owned();
            for arg in args {
                rendered.push(' ');
                rendered.push_str(arg);
            }
            rendered
        }
    }
}

#[async_trait]
impl Exec for ScriptedExec {
    async fn run(&self, spec: &ExecSpec) -> Result<ExecResult> {
        self.answer(spec)
    }

    async fn run_streaming(
        &self,
        spec: &ExecSpec,
        controls: ExecControls,
    ) -> Result<ExecStreamingResult> {
        let result = self.answer(spec)?;
        if !Self::is_probe(spec) {
            self.term_stops
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(controls.term.is_some());
        }
        if let Some(mut reader) = controls.stdin_reader(spec) {
            let mut bytes = Vec::new();
            reader
                .read_to_end(&mut bytes)
                .await
                .map_err(|error| Error::io("reading scripted stdin", error))?;
            if !Self::is_probe(spec) {
                self.stdin
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .push(bytes);
            }
        }
        if let Some(sink) = &controls.sink {
            if !result.stdout.is_empty() {
                sink(OutputStream::Stdout, result.stdout.clone()).await?;
            }
            if !result.stderr.is_empty() {
                sink(OutputStream::Stderr, result.stderr.clone()).await?;
            }
        }
        // The scripted output is what the process wrote; the result keeps
        // only what the caller's retention cap allows, as a provider would.
        let (stdout, stdout_capture) = retain(&result.stdout, controls.retained_output_limit);
        let (stderr, stderr_capture) = retain(&result.stderr, controls.retained_output_limit);
        let mut result = result;
        result.stdout = stdout;
        result.stderr = stderr;
        let mut streaming = ExecStreamingResult::new(result);
        streaming.stdout_capture = stdout_capture;
        streaming.stderr_capture = stderr_capture;
        streaming.streams_separated = self.streams_separated.load(Ordering::SeqCst);
        streaming.live_streaming = true;
        Ok(streaming)
    }

    async fn spawn_stdio(&self, _spec: &SpawnSpec) -> Result<StdioProcess> {
        if let Some(message) = self
            .stdio_error
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
        {
            return Err(Error::Transport(TransportError::new(message)));
        }
        let Some(process) = self
            .stdio
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
        else {
            return Err(Error::Transport(TransportError::new(
                "no scripted stdio process was set",
            )));
        };
        Ok(process.start())
    }
}

/// The bytes of one stream a result keeps under `cap`, and the accounting.
fn retain(output: &[u8], cap: Option<usize>) -> (Vec<u8>, CaptureStats) {
    let mut buffer = OutputCaptureBuffer::new(cap);
    buffer.push(output);
    buffer.into_parts()
}

/// The process side of a scripted stdio spawn.
type StdioDriver = Box<dyn FnOnce(DuplexStream, DuplexStream, StderrTail) + Send + 'static>;

/// A stdio process whose behaviour is a closure the test writes.
///
/// The driver receives the process's end of standard input (read what
/// the consumer writes), its end of standard output (write what the
/// consumer reads), and the stderr tail to push diagnostics into. It runs
/// on its own task as soon as the process is spawned.
pub struct ScriptedStdioProcess {
    exit_code:  Option<i32>,
    wait_delay: Duration,
    driver:     StdioDriver,
}

impl ScriptedStdioProcess {
    pub fn new(
        driver: impl FnOnce(DuplexStream, DuplexStream, StderrTail) + Send + 'static,
    ) -> Self {
        Self {
            exit_code:  Some(0),
            wait_delay: Duration::ZERO,
            driver:     Box::new(driver),
        }
    }

    /// The exit code `wait` reports; `Some(0)` by default.
    #[must_use]
    pub fn exit_code(mut self, exit_code: Option<i32>) -> Self {
        self.exit_code = exit_code;
        self
    }

    /// How long `wait` takes to return.
    #[must_use]
    pub fn wait_delay(mut self, delay: Duration) -> Self {
        self.wait_delay = delay;
        self
    }

    fn start(self) -> StdioProcess {
        let (stdin_consumer, stdin_process) = duplex(64 * 1024);
        let (stdout_process, stdout_consumer) = duplex(64 * 1024);
        let stderr_tail = StderrTail::default();
        let driver_tail = stderr_tail.clone();
        let driver = self.driver;
        tokio::spawn(async move {
            // The driver is synchronous by signature; it may move the
            // streams into tasks of its own.
            driver(stdin_process, stdout_process, driver_tail);
        });
        StdioProcess {
            stdin: Box::pin(stdin_consumer),
            stdout: Box::pin(stdout_consumer),
            stderr_tail,
            handle: Box::new(ScriptedHandle {
                exit_code:  self.exit_code,
                wait_delay: self.wait_delay,
                terminated: AtomicBool::new(false),
            }),
        }
    }
}

struct ScriptedHandle {
    exit_code:  Option<i32>,
    wait_delay: Duration,
    terminated: AtomicBool,
}

#[async_trait]
impl StdioProcessHandle for ScriptedHandle {
    async fn terminate(&self) {
        self.terminated.store(true, Ordering::SeqCst);
    }

    async fn wait(&self) -> (Termination, Option<i32>) {
        if !self.wait_delay.is_zero() {
            sleep(self.wait_delay).await;
        }
        if self.terminated.load(Ordering::SeqCst) {
            return (Termination::Cancelled, None);
        }
        (Termination::Exited, self.exit_code)
    }
}
