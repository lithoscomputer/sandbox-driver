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
    AccessScope, CommandError, Error, ExecControls, ExecSpec, FileRange, GrepMatch, GrepOptions,
    LabelFilter, MutationOutcome, OutputSink, Sandbox, SandboxRef, SandboxState, Sandboxes,
    Termination, WalkOptions, glob_files, grep_files, run_bash, walk_files,
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
    search:      bool,
    pub timeout: Duration,
}

/// What a check does with its freshly created sandbox.
enum Scenario<'a> {
    Identity,
    Files,
    Exec,
    Bash,
    DerivedSearch,
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
            search: false,
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

    /// Declares that the environment's workload provides Bash with `find`,
    /// `head`, `ln` and either ripgrep or GNU or BSD `grep`, which adds a
    /// check of the search the library derives over exec. `BusyBox` `grep`
    /// is not enough.
    #[must_use]
    pub fn with_search(mut self) -> Self {
        self.search = true;
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
        if self.search {
            scenarios.push(("derived_search", Scenario::DerivedSearch));
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
                    Scenario::DerivedSearch => Self::derived_search(sandbox).await,
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
    async fn derived_search(sandbox: &dyn Sandbox) -> CheckOutcome {
        let root = "conformance/search";
        let main = "fn main() {}\nlet Needle = 1;\n";
        for (path, content) in [
            ("top.txt", "top\n"),
            ("src/main.rs", main),
            // A `:` in a file name must not be read as the line separator.
            ("src/with:colon.txt", "a needle: here\n"),
            ("node_modules/dep/index.js", "needle\n"),
            // A file named like an excluded directory is not excluded.
            ("docs/node_modules", "plain\n"),
        ] {
            sandbox
                .files()
                .put(
                    &format!("{root}/{path}"),
                    Box::pin(Cursor::new(content.as_bytes().to_vec())),
                )
                .await?;
        }
        let linked = run_bash(sandbox, "ln -s search conformance/linked").await?;
        require(linked.success(), "the workload could not create a link")?;

        let grep = async |pattern: &str, path: &str, options: &GrepOptions| {
            let mut matches = grep_files(sandbox, pattern, path, options).await?;
            matches.sort_by(|left, right| left.path.cmp(&right.path));
            Ok::<_, CommandError>(matches)
        };
        let colon = GrepMatch::new(format!("{root}/src/with:colon.txt"), 1, "a needle: here");
        let found = grep("needle", root, &GrepOptions::default()).await?;
        let expected = [
            GrepMatch::new(format!("{root}/node_modules/dep/index.js"), 1, "needle"),
            colon.clone(),
        ];
        require(
            found == expected,
            &format!("grep of a directory returned {found:?}, expected {expected:?}"),
        )?;
        // Searching one file still names it.
        let found = grep("needle", &colon.path, &GrepOptions::default()).await?;
        require(
            found == [colon],
            &format!("grep of one file returned {found:?}"),
        )?;
        let mut options = GrepOptions::default();
        options.case_insensitive = true;
        options.include = Some("*.rs".to_owned());
        let found = grep("needle", root, &options).await?;
        require(
            found
                == [GrepMatch::new(
                    format!("{root}/src/main.rs"),
                    2,
                    "let Needle = 1;",
                )],
            &format!("a case-insensitive grep of *.rs returned {found:?}"),
        )?;
        let mut options = GrepOptions::default();
        options.case_insensitive = true;
        options.max_matches = Some(2);
        let found = grep("needle", root, &options).await?;
        require(
            found.len() == 2,
            &format!("grep with max_matches 2 returned {found:?}"),
        )?;
        require(
            grep("no-such-text", root, &GrepOptions::default())
                .await?
                .is_empty(),
            "grep with no match was not empty",
        )?;
        // A search that could not run is not "no match".
        for options in [GrepOptions::default(), options] {
            require(
                matches!(
                    grep("needle", "conformance/absent", &options).await,
                    Err(CommandError::Failed(_))
                ),
                "grep of a missing path did not fail",
            )?;
        }

        let walk = async |base: &str, options: &WalkOptions| {
            let files = walk_files(sandbox, base, options).await?;
            // A size is reported or not as the workload's `find` allows,
            // but a reported one is the file's.
            let sized = files.iter().all(|file| match file.path.as_str() {
                "src/main.rs" => file.size.is_none_or(|size| size == main.len() as u64),
                _ => true,
            });
            let paths: Vec<String> = files.into_iter().map(|file| file.path).collect();
            Ok::<_, CommandError>((paths, sized))
        };
        let (paths, sized) = walk(root, &WalkOptions::default()).await?;
        let everything = [
            "docs/node_modules",
            "node_modules/dep/index.js",
            "src/main.rs",
            "src/with:colon.txt",
            "top.txt",
        ];
        require(
            paths == everything,
            &format!("walk returned {paths:?}, expected {everything:?}"),
        )?;
        require(sized, "walk reported a wrong size")?;
        let mut options = WalkOptions::default();
        options.exclude_dirs = vec!["node_modules".to_owned()];
        let (paths, _) = walk(root, &options).await?;
        require(
            paths
                == [
                    "docs/node_modules",
                    "src/main.rs",
                    "src/with:colon.txt",
                    "top.txt",
                ],
            &format!("walk without node_modules returned {paths:?}"),
        )?;
        let mut options = WalkOptions::default();
        options.max_depth = Some(1);
        let (paths, _) = walk(root, &options).await?;
        require(
            paths == ["top.txt"],
            &format!("walk at depth 1 returned {paths:?}"),
        )?;
        // A missing root is empty, and so is one reached through a link.
        for base in [
            "conformance/absent",
            "conformance/linked",
            "conformance/linked/src",
        ] {
            let (paths, _) = walk(base, &WalkOptions::default()).await?;
            require(
                paths.is_empty(),
                &format!("walk of {base} returned {paths:?}"),
            )?;
        }

        for (pattern, expected) in [
            ("src/*.rs", vec!["src/main.rs"]),
            ("*.txt", vec!["top.txt"]),
            ("**/*.txt", vec!["src/with:colon.txt", "top.txt"]),
        ] {
            let paths = glob_files(sandbox, pattern, root).await?;
            require(
                paths == expected,
                &format!("glob {pattern} returned {paths:?}, expected {expected:?}"),
            )?;
        }
        require(
            matches!(
                glob_files(sandbox, "src/[", root).await,
                Err(CommandError::Sandbox(Error::InvalidSpec { .. }))
            ),
            "an invalid glob was not InvalidSpec",
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
