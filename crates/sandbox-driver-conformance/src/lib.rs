//! Reusable conformance checks for `sandbox_driver` providers.
//!
//! This suite verifies the common lifecycle, routing, streaming, and file
//! surface. Provider-specific workload targeting, optional services/containers,
//! crash recovery and fault injection remain separate integration gates; a
//! passing report does not certify those unexecuted scenarios.
use std::future;
use std::io::Cursor;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use sandbox_driver::{
    AccessScope, CommandError, Error, ExecControls, ExecSpec, FileKind, FileRange, LabelFilter,
    MutationOutcome, OutputSink, Sandbox, SandboxRef, SandboxState, Sandboxes, Termination,
    create_dir_all, path_exists, remove_path, rename_path, run_bash, stat_path,
};
use tokio::io::AsyncReadExt;
use tokio::sync::mpsc;
use tokio::time;

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
    pub timeout: Duration,
}

/// What a check does with its freshly created sandbox.
enum Scenario<'a> {
    Identity,
    Files,
    Exec,
    Bash,
    DerivedFiles,
    /// Stops the sandbox through a handle attached from this catalog.
    Fence(&'a Sandboxes),
}

impl From<CommandError> for Verdict {
    fn from(error: CommandError) -> Self {
        // The log form includes the command's output; a conformance run
        // holds no credentials.
        Self::Failed(match error.failure() {
            Some(failure) => failure.display_for_log(),
            None => error.to_string(),
        })
    }
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

    /// Declares that the environment's workload provides Bash with `stat`,
    /// `mv`, `rm`, `rmdir`, `mkdir` and `ln`. It adds a check that the
    /// provider carries a Bash spec's argv intact, keeps stdout and stderr
    /// apart, and reports the script's exit code, and a check of the file
    /// operations the library derives over exec. The exec contract itself
    /// assumes no shell, so the checks are opt-in.
    #[must_use]
    pub fn with_bash(mut self) -> Self {
        self.bash = true;
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
            scenarios.push(("derived_files", Scenario::DerivedFiles));
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
                    Scenario::DerivedFiles => Self::derived_files(sandbox).await,
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
    async fn derived_files(sandbox: &dyn Sandbox) -> CheckOutcome {
        // A quote, a space, a leading dash and a substitution: each must
        // reach the workload as part of one path.
        let dir = "conformance/derived/it's -a $(dir)";
        let file = format!("{dir}/data.bin");
        let moved = format!("{dir}/moved.bin");
        let link = format!("{dir}/link");

        create_dir_all(sandbox, dir).await?;
        create_dir_all(sandbox, dir).await?;
        require(
            stat_path(sandbox, dir).await?.kind == FileKind::Directory,
            "a created directory was not a directory",
        )?;
        require(
            !path_exists(sandbox, &file).await?,
            "a file existed before it was written",
        )?;
        require(
            is_not_found(&stat_path(sandbox, &file).await),
            "stat of a missing path was not NotFound",
        )?;

        sandbox
            .files()
            .put(&file, Box::pin(Cursor::new(b"12345".to_vec())))
            .await?;
        let stat = stat_path(sandbox, &file).await?;
        require(
            stat.kind == FileKind::File && stat.size == 5,
            "stat did not report a five-byte file",
        )?;
        // Which time a provider gives a file it writes is its own business;
        // Docker's is the epoch.
        require(
            stat.mode.is_some() && stat.modified_at_ms.is_some(),
            "stat did not report a mode and a modification time",
        )?;

        rename_path(sandbox, &file, &moved).await?;
        require(
            !path_exists(sandbox, &file).await? && path_exists(sandbox, &moved).await?,
            "rename did not move the file",
        )?;
        require(
            is_not_found(&rename_path(sandbox, &file, &moved).await),
            "rename of a missing path was not NotFound",
        )?;

        // A link to a directory is described and removed as the link.
        let linked = run_bash(
            sandbox,
            r#"cd "conformance/derived/it's -a \$(dir)" && ln -s . link"#,
        )
        .await?;
        require(linked.success(), "the workload could not create a link")?;
        require(
            stat_path(sandbox, &link).await?.kind == FileKind::Symlink,
            "stat followed a symbolic link",
        )?;
        remove_path(sandbox, &link, false).await?;
        require(
            !path_exists(sandbox, &link).await? && path_exists(sandbox, &moved).await?,
            "removing a link did not remove only the link",
        )?;

        require(
            matches!(
                remove_path(sandbox, dir, false).await,
                Err(CommandError::Failed(_))
            ),
            "a directory with a file in it was removed without recursive",
        )?;
        remove_path(sandbox, &moved, false).await?;
        remove_path(sandbox, &moved, false).await?;
        remove_path(sandbox, dir, false).await?;
        require(
            !path_exists(sandbox, dir).await?,
            "an empty directory was not removed",
        )?;

        create_dir_all(sandbox, &format!("{dir}/a/b")).await?;
        remove_path(sandbox, "conformance/derived", true).await?;
        require(
            !path_exists(sandbox, "conformance/derived").await?,
            "a recursive remove left the directory",
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
fn is_not_found<T>(result: &Result<T, CommandError>) -> bool {
    matches!(result, Err(CommandError::Sandbox(Error::NotFound { .. })))
}
fn require(condition: bool, message: &str) -> CheckOutcome {
    if condition { Ok(()) } else { fail(message) }
}
