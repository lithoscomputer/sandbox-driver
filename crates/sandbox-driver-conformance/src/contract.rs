//! Reusable checks for the additive `sandbox_driver::contract` API.
//!
//! This suite verifies the common lifecycle, routing, streaming, and file
//! surface. Provider-specific workload targeting, optional services/containers,
//! crash recovery and fault injection remain separate integration gates; a
//! passing report does not certify those unexecuted scenarios.
use std::io::Cursor;
use std::sync::Arc;
use std::time::Duration;

use sandbox_driver::contract::{
    AccessScope, Error, ExecControls, ExecSpec, FileRange, LabelFilter, MutationOutcome,
    OutputSink, Sandbox, SandboxRef, SandboxState, Sandboxes, Termination,
};
use tokio::io::AsyncReadExt;
use tokio::sync::{Mutex, mpsc};
use tokio::time;

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
    pub timeout: Duration,
}

#[derive(Clone, Debug)]
pub struct Check {
    pub name:   &'static str,
    pub result: Result<(), Error>,
}
#[derive(Clone, Debug)]
pub struct Report {
    pub checks: Vec<Check>,
}
impl Report {
    pub fn passed(&self) -> bool {
        self.checks.iter().all(|check| check.result.is_ok())
    }
    pub fn assert_pass(&self) {
        assert!(
            self.passed(),
            "new-contract conformance failed: {:#?}",
            self.checks
        );
    }
}

impl Conformance {
    pub fn new(catalog: Sandboxes, environment: impl Into<String>, commands: Commands) -> Self {
        Self {
            catalog,
            peer: None,
            environment: environment.into(),
            commands,
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

    /// Creates one sandbox per check, then attempts bounded cleanup even after
    /// a check fails or times out. Unknown create outcomes have no guessed ID;
    /// providers/applications must reconcile those through inventory.
    pub async fn run(&self) -> Report {
        let mut checks = Vec::new();
        let mut names = vec![
            "identity_and_inventory",
            "binary_files",
            "streamed_exec",
            "cross_handle_stop_fence",
        ];
        if self.peer.is_some() {
            names.push("cross_instance_stop_fence");
        }
        for name in names {
            let reference = Mutex::new(None);
            let operation = async {
                let sandbox = self
                    .catalog
                    .builder(&self.environment)
                    .await?
                    .label("conformance", "quotes='\" unicode=λ newline=\n")
                    .create()
                    .await?;
                *reference.lock().await = Some(sandbox.reference());
                match name {
                    "identity_and_inventory" => self.identity(sandbox.as_ref()).await,
                    "binary_files" => Self::files(sandbox.as_ref()).await,
                    "streamed_exec" => self.exec(sandbox.as_ref()).await,
                    "cross_instance_stop_fence" => {
                        let peer = self.peer.as_ref().expect("peer check requires peer");
                        self.fence_with(sandbox.as_ref(), peer).await
                    }
                    _ => self.fence_with(sandbox.as_ref(), &self.catalog).await,
                }
            };
            let result = time::timeout(self.timeout, operation)
                .await
                .unwrap_or_else(|_| {
                    Err(failed(
                        "conformance check deadline elapsed; outcome unknown",
                    ))
                });
            checks.push(Check { name, result });
            if let Some(reference) = reference.lock().await.take() {
                checks.push(Check {
                    name:   "cleanup",
                    result: self.cleanup(&reference).await,
                });
            }
        }
        Report { checks }
    }
    async fn cleanup(&self, reference: &SandboxRef) -> Result<(), Error> {
        time::timeout(self.timeout, self.catalog.destroy(reference))
            .await
            .unwrap_or_else(|_| Err(failed("cleanup deadline elapsed; removal unconfirmed")))?;
        match time::timeout(self.timeout, self.catalog.attach(reference)).await {
            Ok(Err(Error::NotFound { .. })) => Ok(()),
            _ => Err(failed("destroy did not establish authoritative absence")),
        }
    }
    async fn identity(&self, sandbox: &dyn Sandbox) -> Result<(), Error> {
        let status = sandbox.status().await?;
        require(
            status.state == SandboxState::Running,
            "create did not reach running",
        )?;
        require(
            status.reference == sandbox.reference(),
            "status changed reference",
        )?;
        let attached = self.catalog.attach(&sandbox.reference()).await?;
        require(
            attached.reference() == sandbox.reference(),
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
            .find(LabelFilter::eq(
                "conformance",
                "quotes='\" unicode=λ newline=\n",
            ))
            .await?;
        require(
            !found.unavailable.contains(&sandbox.reference().provider),
            "own provider failed inventory",
        )?;
        require(
            found
                .sandboxes
                .iter()
                .any(|summary| summary.reference == sandbox.reference()),
            "label did not round-trip through inventory",
        )
    }
    async fn files(sandbox: &dyn Sandbox) -> Result<(), Error> {
        let path = "conformance/nested/binary.dat";
        let payload = vec![0, 255, 1, 13, 10, 128, 0];
        sandbox
            .files()
            .put(path, Box::pin(Cursor::new(payload.clone())))
            .await?;
        let mut bytes = Vec::new();
        sandbox
            .files()
            .get(path, None)
            .await?
            .read_to_end(&mut bytes)
            .await
            .map_err(|_| failed("file transfer failed"))?;
        require(bytes == payload, "file bytes changed")?;
        bytes.clear();
        sandbox
            .files()
            .get(
                path,
                Some(FileRange {
                    offset: 1,
                    length: Some(3),
                }),
            )
            .await?
            .read_to_end(&mut bytes)
            .await
            .map_err(|_| failed("range transfer failed"))?;
        require(bytes == payload[1..4], "file range ignored")?;
        let entries = sandbox.files().list("conformance/nested", 0).await?;
        require(
            entries.iter().any(|entry| {
                entry.path.ends_with("binary.dat") && entry.size == payload.len() as u64
            }),
            "file missing from list",
        )?;
        sandbox.stop().await?;
        sandbox.start().await?;
        bytes.clear();
        sandbox
            .files()
            .get(path, None)
            .await?
            .read_to_end(&mut bytes)
            .await
            .map_err(|_| failed("file read after restart failed"))?;
        require(bytes == payload, "stop/start lost workspace")
    }
    async fn exec(&self, sandbox: &dyn Sandbox) -> Result<(), Error> {
        let output = Arc::new(Mutex::new(Vec::new()));
        let capture = Arc::clone(&output);
        let sink: OutputSink = Arc::new(move |_, bytes| {
            let capture = Arc::clone(&capture);
            Box::pin(async move {
                let mut output = capture.lock().await;
                if output.len().saturating_add(bytes.len()) > 65536 {
                    return Err(failed("probe output exceeded 64 KiB"));
                }
                output.extend(bytes);
                Ok(())
            })
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
            *output.lock().await == self.commands.probe_output,
            "probe output differed",
        )
    }
    async fn fence_with(&self, sandbox: &dyn Sandbox, catalog: &Sandboxes) -> Result<(), Error> {
        let attached = match catalog.attach(&sandbox.reference()).await {
            Ok(attached) => attached,
            Err(Error::Busy { .. })
                if catalog
                    .provider(sandbox.reference().provider.as_str())?
                    .describe()
                    .await?
                    .access
                    == AccessScope::OwnerProcess =>
            {
                return Ok(());
            }
            Err(error) => return Err(error),
        };
        let (ready, mut receiver) = mpsc::channel(1);
        let sink: OutputSink = Arc::new(move |_, _| {
            let ready = ready.clone();
            Box::pin(async move {
                let _ = ready.try_send(());
                Ok(())
            })
        });
        let exec = sandbox.exec(self.commands.long_running.clone(), ExecControls {
            sink: Some(sink),
            ..ExecControls::default()
        });
        let stop = async {
            receiver
                .recv()
                .await
                .ok_or_else(|| failed("execution ended without readiness output"))?;
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
fn failed(message: &str) -> Error {
    Error::Transport {
        message: message.into(),
        outcome: MutationOutcome::Unknown,
    }
}
fn require(condition: bool, message: &str) -> Result<(), Error> {
    if condition {
        Ok(())
    } else {
        Err(failed(message))
    }
}
