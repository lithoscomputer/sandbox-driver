//! Reusable conformance checks for `sandbox_driver` providers.
//!
//! This suite verifies the common lifecycle, routing, streaming, and file
//! surface. Provider-specific workload targeting, optional services/containers,
//! crash recovery and fault injection remain separate integration gates; a
//! passing report does not certify those unexecuted scenarios.
use std::future::{self, Future};
use std::io::Cursor;
use std::pin::{Pin, pin};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use sandbox_driver::{
    AccessScope, Error, ExecControls, ExecOutcome, ExecSpec, FileRange, LabelFilter,
    MutationOutcome, OutputSink, OutputStream, Sandbox, SandboxRef, SandboxState, Sandboxes,
    TerminalSize, Termination, run_bash,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream, duplex};
use tokio::sync::{mpsc, watch};
use tokio::time;
use tokio_util::sync::CancellationToken;

use crate::check::{CheckOutcome, Verdict, fail};

mod check;
#[doc(hidden)]
pub mod legacy;
mod report;

pub use report::{CheckResult, Outcome, Report};

/// Every check's sandbox carries this label; the awkward value proves it
/// round-trips through inventory unchanged.
const LABEL_KEY: &str = "conformance";
const LABEL_VALUE: &str = "quotes='\" unicode=λ newline=\n";

/// Probe output beyond this fails the sink rather than buffering unbounded.
const PROBE_OUTPUT_LIMIT: usize = 64 * 1024;

/// Provider-specific commands used to exercise execution without assuming a
/// shell exists. `probe` must emit `probe_output` and exit zero. `long_running`
/// must emit at least one chunk, then remain running until stopped.
#[derive(Clone, Debug)]
pub struct Commands {
    pub probe:        ExecSpec,
    pub probe_output: Vec<u8>,
    pub long_running: ExecSpec,
}

pub struct Conformance {
    catalog:     Sandboxes,
    peer:        Option<Sandboxes>,
    environment: String,
    commands:    Commands,
    bash:        bool,
    terminal:    bool,
    pub timeout: Duration,
}

/// What a check does with its freshly created sandbox.
enum Scenario<'a> {
    Identity,
    Files,
    Exec,
    Bash,
    Terminal,
    /// Stops the sandbox through a handle attached from this catalog.
    Fence(&'a Sandboxes),
}

impl From<Error> for Verdict {
    fn from(error: Error) -> Self {
        Self::Failed(error.to_string())
    }
}

impl Conformance {
    pub fn new(catalog: Sandboxes, environment: impl Into<String>, commands: Commands) -> Self {
        Self {
            catalog,
            peer: None,
            environment: environment.into(),
            commands,
            bash: false,
            terminal: false,
            timeout: Duration::from_secs(30),
        }
    }
    /// Supplies a separately activated catalog to verify fencing across
    /// provider instances. It must bind the same entry name and namespace.
    #[must_use]
    pub fn with_peer(mut self, peer: Sandboxes) -> Self {
        self.peer = Some(peer);
        self
    }

    /// Declares that the environment's workload provides Bash, which adds a
    /// check that the provider carries a Bash spec's argv intact, keeps
    /// stdout and stderr apart, and reports the script's exit code. The exec
    /// contract itself assumes no shell, so the check is opt-in.
    #[must_use]
    pub fn with_bash(mut self) -> Self {
        self.bash = true;
        self
    }

    /// Declares that the provider runs commands on a terminal
    /// (`ExecSpec::tty`) and that the workload provides Bash and `stty`,
    /// which adds a check that a command sees a terminal of the requested
    /// size, follows a resize, reads its input from the terminal, writes one
    /// terminal stream, that the interrupt character stops it, and that
    /// `term` ends an interactive shell on it. Opt-in until every built-in
    /// provider runs commands on a terminal.
    #[must_use]
    pub fn with_terminal(mut self) -> Self {
        self.terminal = true;
        self
    }

    /// Creates one sandbox per check, then attempts bounded cleanup even after
    /// a check fails or times out; a cleanup failure fails its check. Unknown
    /// create outcomes have no guessed ID; providers/applications must
    /// reconcile those through inventory.
    pub async fn run(&self) -> Report {
        let mut scenarios = vec![
            ("identity_and_inventory", Scenario::Identity),
            ("binary_files", Scenario::Files),
            ("streamed_exec", Scenario::Exec),
            ("cross_handle_stop_fence", Scenario::Fence(&self.catalog)),
        ];
        if self.bash {
            scenarios.push(("captured_bash", Scenario::Bash));
        }
        if self.terminal {
            scenarios.push(("terminal_exec", Scenario::Terminal));
        }
        if let Some(peer) = &self.peer {
            scenarios.push(("cross_instance_stop_fence", Scenario::Fence(peer)));
        }
        let mut results = Vec::new();
        for (name, scenario) in scenarios {
            let mut reference = None;
            let operation = async {
                let sandbox = self
                    .catalog
                    .builder(&self.environment)
                    .await?
                    .label(LABEL_KEY, LABEL_VALUE)
                    .create()
                    .await?;
                reference = Some(sandbox.reference());
                let sandbox = sandbox.as_ref();
                match scenario {
                    Scenario::Identity => self.identity(sandbox).await,
                    Scenario::Files => Self::files(sandbox).await,
                    Scenario::Exec => self.exec(sandbox).await,
                    Scenario::Bash => Self::bash(sandbox).await,
                    Scenario::Terminal => Self::terminal(sandbox).await,
                    Scenario::Fence(catalog) => self.fence_with(sandbox, catalog).await,
                }
            };
            let result = time::timeout(self.timeout, operation)
                .await
                .unwrap_or_else(|_| fail("conformance check deadline elapsed; outcome unknown"));
            let cleanup = match reference {
                Some(reference) => self.cleanup(&reference).await,
                None => Ok(()),
            };
            let outcome = match (result, cleanup) {
                (Err(Verdict::Failed(reason)), Err(cleanup)) => Outcome::Failed {
                    reason: format!("{reason}; cleanup: {cleanup}"),
                },
                (_, Err(cleanup)) => Outcome::Failed {
                    reason: format!("cleanup: {cleanup}"),
                },
                (Ok(()), Ok(())) => Outcome::Passed,
                (Err(Verdict::Skipped(reason)), Ok(())) => Outcome::Skipped { reason },
                (Err(Verdict::Failed(reason)), Ok(())) => Outcome::Failed { reason },
            };
            results.push(CheckResult { name, outcome });
        }
        Report { results }
    }
    async fn cleanup(&self, reference: &SandboxRef) -> Result<(), String> {
        match time::timeout(self.timeout, self.catalog.destroy(reference)).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => return Err(format!("destroy failed: {error}")),
            Err(_) => return Err("destroy deadline elapsed; removal unconfirmed".into()),
        }
        match time::timeout(self.timeout, self.catalog.attach(reference)).await {
            Ok(Err(Error::NotFound { .. })) => Ok(()),
            Ok(Ok(_)) => Err("sandbox still attachable after destroy".into()),
            Ok(Err(error)) => Err(format!("absence unconfirmed after destroy: {error}")),
            Err(_) => Err("absence check deadline elapsed".into()),
        }
    }
    async fn identity(&self, sandbox: &dyn Sandbox) -> CheckOutcome {
        let reference = sandbox.reference();
        let status = sandbox.status().await?;
        require(
            status.state == SandboxState::Running,
            "create did not reach running",
        )?;
        require(status.reference == reference, "status changed reference")?;
        let attached = self.catalog.attach(&reference).await?;
        require(
            attached.reference() == reference,
            "attach changed reference",
        )?;
        require(
            attached.env() == sandbox.env(),
            "attach changed effective environment",
        )?;
        require(
            attached.working_directory() == sandbox.working_directory(),
            "attach changed workspace",
        )?;
        let found = self
            .catalog
            .find(LabelFilter::eq(LABEL_KEY, LABEL_VALUE))
            .await?;
        require(
            !found.unavailable.contains(&reference.provider),
            "own provider failed inventory",
        )?;
        require(
            found
                .sandboxes
                .iter()
                .any(|summary| summary.reference == reference),
            "label did not round-trip through inventory",
        )
    }
    async fn files(sandbox: &dyn Sandbox) -> CheckOutcome {
        let path = "conformance/nested/binary.dat";
        let payload = vec![0, 255, 1, 13, 10, 128, 0];
        sandbox
            .files()
            .put(path, Box::pin(Cursor::new(payload.clone())))
            .await?;
        require(
            read(sandbox, path, None).await? == payload,
            "file bytes changed",
        )?;
        let range = Some(FileRange {
            offset: 1,
            length: Some(3),
        });
        require(
            read(sandbox, path, range).await? == payload[1..4],
            "file range ignored",
        )?;
        let entries = sandbox.files().list("conformance/nested", 0).await?;
        require(
            entries.iter().any(|entry| {
                entry.path.ends_with("binary.dat") && entry.size == payload.len() as u64
            }),
            "file missing from list",
        )?;
        sandbox.stop().await?;
        sandbox.start().await?;
        require(
            read(sandbox, path, None).await? == payload,
            "stop/start lost workspace",
        )
    }
    async fn exec(&self, sandbox: &dyn Sandbox) -> CheckOutcome {
        let output = Arc::new(Mutex::new(Vec::new()));
        let capture = Arc::clone(&output);
        let sink: OutputSink = Arc::new(move |_, bytes| {
            let mut output = capture.lock().expect("probe output lock");
            let result = if output.len().saturating_add(bytes.len()) > PROBE_OUTPUT_LIMIT {
                Err(Error::Transport {
                    message: "probe output exceeded 64 KiB".into(),
                    outcome: MutationOutcome::Unknown,
                })
            } else {
                output.extend(bytes);
                Ok(())
            };
            Box::pin(future::ready(result))
        });
        let outcome = sandbox
            .exec(self.commands.probe.clone(), ExecControls {
                sink: Some(sink),
                ..ExecControls::default()
            })
            .await?;
        require(
            outcome.termination == Termination::Exited && outcome.exit_code == Some(0),
            "probe did not exit successfully",
        )?;
        require(!outcome.output_loss.is_lossy(), "probe output was lost")?;
        require(
            *output.lock().expect("probe output lock") == self.commands.probe_output,
            "probe output differed",
        )
    }
    async fn bash(sandbox: &dyn Sandbox) -> CheckOutcome {
        let script = "printf 'to stdout'; printf 'to stderr' >&2; exit 3";
        let captured = run_bash(sandbox, script).await?;
        require(
            captured.outcome.termination == Termination::Exited
                && captured.outcome.exit_code == Some(3),
            "the script's exit status was not the command's",
        )?;
        require(captured.is_complete(), "bash output was lost")?;
        require(
            captured.stdout.bytes == b"to stdout",
            "bash stdout differed",
        )?;
        require(
            captured.stderr.bytes == b"to stderr",
            "bash stderr differed",
        )
    }
    async fn terminal(sandbox: &dyn Sandbox) -> CheckOutcome {
        // Reports the terminal's size, then again for each line it reads.
        let script = r#"stty size; while read -r line && [ "$line" != done ]; do stty size; done; echo finished"#;
        let (resize, resized) = watch::channel(terminal_size(30, 100));
        let (mut terminal, exec) =
            Terminal::start(sandbox, ExecSpec::bash(script), Some(resized), None);
        let mut exec = pin!(exec);
        terminal.wait_for(exec.as_mut(), "30 100").await?;
        resize.send_replace(terminal_size(40, 120));
        // A resize and input travel separately; ask until the new size shows.
        for _ in 0..40 {
            terminal.write(b"\n").await?;
            let shown = time::timeout(
                Duration::from_millis(500),
                terminal.wait_for(exec.as_mut(), "40 120"),
            )
            .await;
            if let Ok(shown) = shown {
                shown?;
                break;
            }
        }
        require(terminal.text().contains("40 120"), "resize not followed")?;
        terminal.write(b"done\n").await?;
        let outcome = terminal.finish(exec).await?;
        require(
            outcome.termination == Termination::Exited && outcome.exit_code == Some(0),
            "terminal command did not exit successfully",
        )?;
        require(terminal.text().contains("finished"), "terminal output lost")?;
        require(
            terminal.one_stream,
            "terminal output arrived on stdout or stderr",
        )?;

        let (mut terminal, exec) = Terminal::start(
            sandbox,
            ExecSpec::bash("echo ready; exec sleep 30"),
            None,
            None,
        );
        let mut exec = pin!(exec);
        terminal.wait_for(exec.as_mut(), "ready").await?;
        terminal.write(&[0x03]).await?;
        let outcome = terminal.finish(exec).await?;
        if !(outcome.termination == Termination::Exited
            && (outcome.signal == Some(2) || outcome.exit_code == Some(130)))
        {
            return fail(format!(
                "the interrupt character did not stop the command: {outcome:?}"
            ));
        }

        // An interactive shell ignores SIGTERM; `term` on a terminal must
        // still end it, as closing the terminal would.
        let term = CancellationToken::new();
        let (mut terminal, exec) = Terminal::start(
            sandbox,
            ExecSpec::argv(["bash", "--norc", "--noprofile", "-i"]),
            None,
            Some(term.clone()),
        );
        let mut exec = pin!(exec);
        terminal.write(b"echo ready-$((40 + 2))\n").await?;
        terminal.wait_for(exec.as_mut(), "ready-42").await?;
        term.cancel();
        let outcome = terminal.finish(exec).await?;
        require(
            outcome.termination == Termination::Terminated,
            &format!("term did not end an interactive shell on a terminal: {outcome:?}"),
        )
    }
    async fn fence_with(&self, sandbox: &dyn Sandbox, catalog: &Sandboxes) -> CheckOutcome {
        let reference = sandbox.reference();
        let attached = match catalog.attach(&reference).await {
            Ok(attached) => attached,
            Err(error @ Error::Busy { .. }) => {
                // An owner-process provider may refuse a second handle
                // instead of joining the fence.
                let access = catalog
                    .provider(reference.provider.as_str())?
                    .describe()
                    .await?
                    .access;
                return if access == AccessScope::OwnerProcess {
                    Ok(())
                } else {
                    Err(error.into())
                };
            }
            Err(error) => return Err(error.into()),
        };
        let (ready, mut receiver) = mpsc::channel(1);
        let sink: OutputSink = Arc::new(move |_, _| {
            let _ = ready.try_send(());
            Box::pin(future::ready(Ok(())))
        });
        let exec = sandbox.exec(self.commands.long_running.clone(), ExecControls {
            sink: Some(sink),
            ..ExecControls::default()
        });
        let stop = async {
            if receiver.recv().await.is_none() {
                return fail("execution ended without readiness output");
            }
            attached.stop().await?;
            require(
                attached.status().await?.state == SandboxState::Stopped,
                "stop did not reach stopped",
            )?;
            attached.start().await?;
            require(
                attached.status().await?.state == SandboxState::Running,
                "restart did not reach running",
            )
        };
        let (execution, stopping) = tokio::join!(exec, stop);
        stopping?;
        let execution = execution?;
        require(
            matches!(
                execution.termination,
                Termination::Killed | Termination::Terminated
            ),
            "stop did not confirm execution termination",
        )
    }
}
async fn read(
    sandbox: &dyn Sandbox,
    path: &str,
    range: Option<FileRange>,
) -> Result<Vec<u8>, Verdict> {
    let mut bytes = Vec::new();
    sandbox
        .files()
        .get(path, range)
        .await?
        .read_to_end(&mut bytes)
        .await
        .map_err(|error| format!("reading {path} failed: {error}"))?;
    Ok(bytes)
}
fn require(condition: bool, message: &str) -> CheckOutcome {
    if condition { Ok(()) } else { fail(message) }
}

fn terminal_size(rows: u16, columns: u16) -> TerminalSize {
    TerminalSize {
        rows:    rows.try_into().expect("non-zero rows"),
        columns: columns.try_into().expect("non-zero columns"),
    }
}

/// A started command, which runs only while polled.
type Running<'a> = Pin<Box<dyn Future<Output = Result<ExecOutcome, Error>> + Send + 'a>>;

/// The caller's side of a command run on a terminal: its input, and the
/// output seen so far.
struct Terminal {
    input:      DuplexStream,
    output:     mpsc::UnboundedReceiver<(OutputStream, Vec<u8>)>,
    seen:       Vec<u8>,
    /// Whether every chunk arrived as the terminal stream.
    one_stream: bool,
}

impl Terminal {
    /// Starts a command on a terminal. The command runs only while the
    /// returned future is polled.
    fn start(
        sandbox: &dyn Sandbox,
        mut spec: ExecSpec,
        resize: Option<watch::Receiver<TerminalSize>>,
        term: Option<CancellationToken>,
    ) -> (Self, Running<'_>) {
        spec.tty = true;
        spec.timeout_ms = Some(20_000);
        let (input, stdin) = duplex(1024);
        let (chunks, output) = mpsc::unbounded_channel();
        let sink: OutputSink = Arc::new(move |stream, bytes| {
            let _ = chunks.send((stream, bytes));
            Box::pin(future::ready(Ok(())))
        });
        let exec = sandbox.exec(spec, ExecControls {
            stdin: Some(Box::pin(stdin)),
            sink: Some(sink),
            resize,
            term,
            ..ExecControls::default()
        });
        (
            Self {
                input,
                output,
                seen: Vec::new(),
                one_stream: true,
            },
            exec,
        )
    }

    fn record(&mut self, (stream, bytes): (OutputStream, Vec<u8>)) {
        self.one_stream &= stream == OutputStream::Terminal;
        self.seen.extend(bytes);
    }

    fn text(&self) -> String {
        String::from_utf8_lossy(&self.seen).into_owned()
    }

    async fn write(&mut self, bytes: &[u8]) -> CheckOutcome {
        self.input
            .write_all(bytes)
            .await
            .map_err(|error| Verdict::Failed(format!("terminal input failed: {error}")))
    }

    /// Runs the command until its output shows `wanted`.
    async fn wait_for(
        &mut self,
        mut exec: Pin<&mut impl Future<Output = Result<ExecOutcome, Error>>>,
        wanted: &str,
    ) -> CheckOutcome {
        while !self.text().contains(wanted) {
            tokio::select! {
                outcome = exec.as_mut() => {
                    return fail(format!("the command ended before it wrote {wanted:?}: {outcome:?}"));
                }
                Some(chunk) = self.output.recv() => self.record(chunk),
            }
        }
        Ok(())
    }

    /// Runs the command to its end and collects the rest of its output.
    async fn finish(
        &mut self,
        mut exec: Pin<&mut impl Future<Output = Result<ExecOutcome, Error>>>,
    ) -> Result<ExecOutcome, Verdict> {
        let outcome = loop {
            tokio::select! {
                outcome = exec.as_mut() => break outcome?,
                Some(chunk) = self.output.recv() => self.record(chunk),
            }
        };
        while let Ok(chunk) = self.output.try_recv() {
            self.record(chunk);
        }
        Ok(outcome)
    }
}
