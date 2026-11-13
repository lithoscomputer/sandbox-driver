//! A Daytona workload behind the shared contract's `Sandbox`.
//!
//! The fence is Daytona's own lifecycle state, read from the control plane
//! that every provider instance shares. Work is admitted only while the
//! sandbox is started; a stop that Daytona confirms ends everything that
//! ran inside it.

use std::collections::{BTreeMap, HashMap};
use std::future;
use std::io::Cursor;
use std::num::{NonZeroU16, NonZeroU32, NonZeroU64};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use sandbox_driver::contract::{
    ByteStream, Containers, Error, ExecControls, ExecOutcome, ExecSpec, Expose, Exposure,
    FileEntry, FileRange, Files, MutationOutcome, OneShotImage, OneShotSpec, OutputSink,
    OutputStream, Ports, Resources, Sandbox, SandboxRef, SandboxState, Status, Termination,
};
use sandbox_driver::{
    ExecControls as LegacyControls, ExecSpec as LegacySpec, ExecStreamingResult,
    OneShotImage as LegacyImage, OneShotSpec as LegacyOneShot, OutputStream as LegacyStream,
    PreviewUrls as _, Sandbox as LegacySandbox, SandboxState as LegacyState, SnapshotId,
    StdinSource, Termination as LegacyTermination, TransportError,
};
use tokio::io::AsyncReadExt;
use tokio::sync::OnceCell;
use tokio::time;
use tokio_util::sync::CancellationToken;

use super::error::{classify, from_sdk, refused};
use super::{runner, spec};
use crate::labels::{IMAGE_LABEL, INTERNAL_PREFIX};
use crate::sandbox::status_from_sdk;
use crate::sdk::{find_sandbox, map_state};
use crate::{DaytonaSandbox, TRANSITION_BUDGET};

/// How often a running command checks whether its sandbox was stopped.
const WATCH_POLL: Duration = Duration::from_secs(2);
/// Bounds every input taken as one buffer: nested stdin and file writes.
/// It is the legacy filesystem's own write limit.
const BUFFER_LIMIT: usize = sandbox_driver::DEFAULT_BUFFER_BYTES;
const DEFAULT_SIGNED_TTL: Duration = Duration::from_secs(3600);

pub(super) struct Workload {
    reference: SandboxRef,
    handle:    Arc<DaytonaSandbox>,
    env:       BTreeMap<String, String>,
    closed:    CancellationToken,
    /// Whether the direct workload provides Docker for one-shots.
    docker:    OnceCell<bool>,
}

impl Workload {
    pub(super) fn new(
        reference: SandboxRef,
        handle: Arc<DaytonaSandbox>,
        env: BTreeMap<String, String>,
        closed: CancellationToken,
    ) -> Self {
        Self {
            reference,
            handle,
            env,
            closed,
            docker: OnceCell::new(),
        }
    }

    fn ensure_open(&self) -> Result<(), Error> {
        super::ensure_open(&self.closed)
    }

    /// Whether the workload runs as a container inside the provider's
    /// runner, beside its services, rather than as the sandbox itself.
    fn nested(&self) -> bool {
        self.handle.runs_in_container()
    }

    /// The sandbox as Daytona has it now, or `None` once Daytona no longer
    /// knows it.
    async fn fetch(&self, operation: &'static str) -> Result<Option<daytona_sdk::Sandbox>, Error> {
        find_sandbox(self.handle.client(), self.handle.sdk_id())
            .await
            .map_err(|error| from_sdk(operation, &error))
    }

    fn absent(&self) -> Error {
        Error::NotFound {
            resource: "sandbox".to_owned(),
            id:       self.reference.id.to_string(),
        }
    }

    /// Daytona's current lifecycle state; a sandbox Daytona no longer knows
    /// is `Deleted`.
    async fn state(&self) -> Result<LegacyState, Error> {
        Ok(self.observe().await?.0)
    }

    /// Daytona's lifecycle state with the record's `updatedAt`, which every
    /// stop and start changes and commands do not.
    async fn observe(&self) -> Result<(LegacyState, Option<String>), Error> {
        Ok(self
            .fetch("fetching sandbox state")
            .await?
            .map_or((LegacyState::Deleted, None), |sdk| {
                (map_state(sdk.state), sdk.updated_at)
            }))
    }

    /// Admits work only into a started sandbox and returns the generation
    /// it was admitted into. Nothing has been sent when this refuses.
    async fn admit(&self) -> Result<Option<String>, Error> {
        self.ensure_open()?;
        let (state, generation) = self.observe().await.map_err(not_started)?;
        // Admit exactly when status reports the workload running.
        match state {
            state if contract_state(state) == SandboxState::Running => Ok(generation),
            LegacyState::Deleted => Err(self.absent()),
            state => Err(Error::Busy {
                message: format!("the sandbox is {state:?}, not started"),
            }),
        }
    }

    fn stopped(state: LegacyState) -> bool {
        matches!(
            state,
            LegacyState::Stopped | LegacyState::Archived | LegacyState::Deleted
        )
    }

    /// Resolves once the sandbox is confirmed stopped; any work admitted
    /// before has then ended with it.
    async fn watch_for_stop(&self) {
        loop {
            time::sleep(WATCH_POLL).await;
            if self.state().await.is_ok_and(Self::stopped) {
                return;
            }
        }
    }

    /// After execution failed: whether a stop explains it, waiting out a
    /// stop in progress within the transition budget. Only a stop Daytona
    /// confirms counts; a sandbox still stopping at the end of the budget,
    /// or in an error state, leaves the command's fate unknown.
    ///
    /// A stop and restart can both finish before this looks (Daytona
    /// restarts in about a second). A sandbox that is running again with a
    /// record changed since admission therefore also counts: the
    /// generation the command ran in has ended.
    async fn ended_by_stop(&self, admitted: Option<&str>) -> bool {
        let started = Instant::now();
        loop {
            let Ok((state, generation)) = self.observe().await else {
                return false;
            };
            match state {
                state if Self::stopped(state) => return true,
                // Admission needs a running sandbox, so one that is coming
                // up again or being archived was stopped in between.
                LegacyState::Starting | LegacyState::Restoring | LegacyState::Archiving => {
                    return true;
                }
                LegacyState::Stopping | LegacyState::Deleting
                    if started.elapsed() < TRANSITION_BUDGET =>
                {
                    time::sleep(WATCH_POLL).await;
                }
                state if contract_state(state) == SandboxState::Running => {
                    return admitted.is_some() && generation.as_deref() != admitted;
                }
                _ => return false,
            }
        }
    }

    /// Runs admitted work under the shared fence: a confirmed stop ends it
    /// as `Killed`, and a failure that leaves its fate unknown is `Lost`.
    async fn fenced(
        &self,
        work: impl Future<Output = sandbox_driver::Result<ExecStreamingResult>>,
        admitted: Option<String>,
    ) -> Result<ExecOutcome, Error> {
        let result = tokio::select! {
            biased;
            result = work => result,
            () = self.watch_for_stop() => return Ok(outcome_of(Termination::Killed)),
            () = self.closed.cancelled() => {
                return Err(Error::Stale { outcome: MutationOutcome::Unknown });
            }
        };
        match result {
            Ok(result) => Ok(outcome(&result)),
            Err(error) => {
                // A stop comes first: Daytona answers polls of a command in
                // a stopping sandbox with 400 as well as 502.
                if self.ended_by_stop(admitted.as_deref()).await {
                    return Ok(outcome_of(Termination::Killed));
                }
                // Only a refusal made here, before anything was sent, proves
                // the command never ran. A 400 from Daytona does not: it
                // answers the output poll of a dead command with one.
                let unsent = matches!(
                    error,
                    sandbox_driver::Error::InvalidSpec { .. }
                        | sandbox_driver::Error::Unsupported { .. }
                );
                let error = classify("running command", error);
                if unsent {
                    return Err(error);
                }
                tracing::warn!(error = ?error, "daytona command outcome unknown");
                Ok(outcome_of(Termination::Lost))
            }
        }
    }

    /// Delivers the legacy output stream through the contract sink.
    /// Standard input is wired by each caller, which knows where it goes.
    fn output_controls(
        sink: Option<OutputSink>,
        term: Option<CancellationToken>,
        kill: Option<CancellationToken>,
    ) -> LegacyControls {
        let mut legacy = LegacyControls {
            term,
            kill,
            ..LegacyControls::default()
        };
        if let Some(sink) = sink {
            legacy.sink = Some(Arc::new(move |stream, bytes| {
                let stream = match stream {
                    LegacyStream::Stdout => OutputStream::Stdout,
                    LegacyStream::Stderr => OutputStream::Stderr,
                };
                let delivery = sink(stream, bytes);
                Box::pin(async move {
                    delivery.await.map_err(|error| {
                        sandbox_driver::Error::Transport(TransportError::new(format!(
                            "output sink failed: {error}"
                        )))
                    })
                })
            }));
        }
        legacy
    }

    /// Reads `input` into one buffer of at most [`BUFFER_LIMIT`] bytes,
    /// refusing a longer input before anything is sent. Docker exec through
    /// Daytona takes stdin this way, and Daytona's file upload takes one body.
    async fn buffered(input: ByteStream, what: &str) -> Result<Vec<u8>, Error> {
        let mut bytes = Vec::new();
        input
            .take(BUFFER_LIMIT as u64 + 1)
            .read_to_end(&mut bytes)
            .await
            .map_err(|_| Error::Transport {
                message: format!("reading {what} failed"),
                outcome: MutationOutcome::NotStarted,
            })?;
        if bytes.len() > BUFFER_LIMIT {
            return Err(Error::Unsupported {
                capability: format!(
                    "{what} beyond {} MiB for this workload",
                    BUFFER_LIMIT / (1024 * 1024)
                ),
            });
        }
        Ok(bytes)
    }

    /// Buffers a nested command's stdin before the command starts. Nothing
    /// has been sent yet, so the fence does not cover this read: the
    /// caller's controls, the command's timeout and the provider's shutdown
    /// end it here, as the termination the command would have reported.
    async fn nested_stdin(
        &self,
        input: ByteStream,
        timeout: Option<Duration>,
        term: Option<&CancellationToken>,
        kill: Option<&CancellationToken>,
    ) -> Result<Result<Vec<u8>, Termination>, Error> {
        let cancelled = |token: Option<&CancellationToken>| {
            let token = token.cloned();
            async move {
                match token {
                    Some(token) => token.cancelled().await,
                    None => future::pending().await,
                }
            }
        };
        let expired = async {
            match timeout {
                Some(timeout) => time::sleep(timeout).await,
                None => future::pending().await,
            }
        };
        tokio::select! {
            biased;
            () = self.closed.cancelled() => Err(Error::Stale {
                outcome: MutationOutcome::NotStarted,
            }),
            () = cancelled(kill) => Ok(Err(Termination::Killed)),
            () = cancelled(term) => Ok(Err(Termination::Terminated)),
            () = expired => Ok(Err(Termination::TimedOut)),
            bytes = Self::buffered(input, "stdin") => bytes.map(Ok),
        }
    }

    /// Whether the direct workload can run one-shot containers on its own
    /// Docker. Checked once per handle.
    async fn has_docker(&self) -> Result<bool, Error> {
        if self.nested() {
            return Ok(true);
        }
        self.docker
            .get_or_try_init(|| async {
                let probe = self
                    .handle
                    .exec()
                    .run(&docker_probe())
                    .await
                    .map_err(|error| classify("probing for Docker", error))?;
                Ok(probe.success())
            })
            .await
            .copied()
    }
}

/// Probes a direct workload for a Docker daemon it can run one-shot
/// containers on.
fn docker_probe() -> LegacySpec {
    LegacySpec::new("sh")
        .args([
            "-c",
            "command -v start-docker >/dev/null && command -v docker >/dev/null && command -v python3 >/dev/null",
        ])
        .timeout(Duration::from_secs(30))
}

fn not_started(error: Error) -> Error {
    match error {
        Error::Unavailable { message, .. } => Error::Unavailable {
            message,
            outcome: MutationOutcome::NotStarted,
        },
        error => error,
    }
}

fn outcome_of(termination: Termination) -> ExecOutcome {
    ExecOutcome {
        termination,
        exit_code: None,
        signal: None,
        output_loss: sandbox_driver::OutputLoss::default(),
    }
}

fn outcome(result: &ExecStreamingResult) -> ExecOutcome {
    let termination = match result.result.termination {
        LegacyTermination::Exited => Termination::Exited,
        LegacyTermination::TimedOut => Termination::TimedOut,
        LegacyTermination::Cancelled => Termination::Terminated,
        LegacyTermination::Killed => Termination::Killed,
        _ => Termination::Lost,
    };
    ExecOutcome {
        termination,
        exit_code: (termination == Termination::Exited)
            .then_some(result.result.exit_code)
            .flatten(),
        signal: result.result.signal,
        output_loss: result.output_loss,
    }
}

fn legacy_spec(spec: &ExecSpec) -> LegacySpec {
    let mut legacy = LegacySpec::new(&spec.argv[0]).args(spec.argv[1..].iter().cloned());
    legacy = match spec.timeout_ms {
        Some(ms) => legacy.timeout(Duration::from_millis(ms)),
        None => legacy.no_timeout(),
    };
    if let Some(dir) = &spec.working_directory {
        legacy = legacy.working_dir(dir);
    }
    for (key, value) in &spec.env {
        legacy = legacy.env_var(key, value);
    }
    legacy
}

/// The contract's view of a Daytona state. Transitions that leave the
/// workload usable read as running.
pub(super) fn contract_state(state: LegacyState) -> SandboxState {
    match state {
        LegacyState::Creating => SandboxState::Creating,
        LegacyState::Starting | LegacyState::Restoring | LegacyState::Resuming => {
            SandboxState::Starting
        }
        LegacyState::Running
        | LegacyState::Snapshotting
        | LegacyState::Forking
        | LegacyState::Resizing => SandboxState::Running,
        LegacyState::Stopping | LegacyState::Pausing | LegacyState::Archiving => {
            SandboxState::Stopping
        }
        LegacyState::Stopped => SandboxState::Stopped,
        LegacyState::Paused => SandboxState::Paused,
        LegacyState::Archived => SandboxState::Archived,
        LegacyState::Deleting => SandboxState::Deleting,
        LegacyState::Deleted => SandboxState::Deleted,
        LegacyState::Error => SandboxState::Unhealthy,
        _ => SandboxState::Unknown,
    }
}

/// The caller's labels, without the provider's own metadata.
pub(super) fn public_labels(labels: &HashMap<String, String>) -> BTreeMap<String, String> {
    labels
        .iter()
        .filter(|(key, _)| !key.starts_with(INTERNAL_PREFIX))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect()
}

fn contract_resources(resources: Option<sandbox_driver::Resources>) -> Resources {
    let Some(resources) = resources else {
        return Resources::default();
    };
    Resources {
        cpu_cores: resources.cpu_cores.and_then(NonZeroU32::new),
        memory_mb: resources.memory_mb.and_then(NonZeroU64::new),
        disk_mb:   resources.disk_mb.and_then(NonZeroU64::new),
        gpus:      resources.gpus,
    }
}

#[async_trait]
impl Sandbox for Workload {
    fn reference(&self) -> SandboxRef {
        self.reference.clone()
    }

    fn working_directory(&self) -> &Path {
        Path::new(LegacySandbox::working_directory(self.handle.as_ref()))
    }

    fn env(&self) -> &BTreeMap<String, String> {
        &self.env
    }

    async fn status(&self) -> Result<Status, Error> {
        self.ensure_open()?;
        let Some(sdk) = self.fetch("fetching sandbox").await? else {
            return Ok(Status {
                reference: self.reference(),
                state:     SandboxState::Deleted,
                name:      None,
                labels:    BTreeMap::new(),
                image:     None,
                snapshot:  None,
                resources: Resources::default(),
                network:   None,
                services:  BTreeMap::new(),
                web_url:   None,
            });
        };
        let legacy = status_from_sdk(self.handle.client(), &sdk)
            .map_err(|error| classify("reading sandbox status", error))?;
        let state = contract_state(legacy.state);
        // Addresses are observed now, never remembered from an earlier boot.
        let services = if self.nested() && state == SandboxState::Running {
            runner::service_addresses(&self.handle).await?
        } else {
            BTreeMap::new()
        };
        Ok(Status {
            reference: self.reference(),
            state,
            name: legacy.name,
            labels: public_labels(&sdk.labels),
            image: sdk.labels.get(IMAGE_LABEL).cloned(),
            snapshot: legacy
                .snapshot
                .and_then(|snapshot| SnapshotId::try_new(snapshot).ok()),
            resources: contract_resources(legacy.resources),
            network: legacy.network.and_then(spec::contract_network),
            services,
            web_url: legacy.web_url,
        })
    }

    #[tracing::instrument(skip_all, fields(sandbox_id = %self.reference.id), err)]
    async fn start(&self) -> Result<(), Error> {
        self.ensure_open()?;
        match self.state().await.map_err(not_started)? {
            LegacyState::Stopping | LegacyState::Pausing | LegacyState::Archiving => {
                return Err(Error::Busy {
                    message: "the previous generation is still stopping".to_owned(),
                });
            }
            LegacyState::Deleting | LegacyState::Deleted => return Err(self.absent()),
            _ => {}
        }
        LegacySandbox::start(self.handle.as_ref())
            .await
            .map_err(|error| classify("starting sandbox", error))?;
        if self.nested() {
            runner::restart_services(&self.handle).await?;
        }
        Ok(())
    }

    #[tracing::instrument(skip_all, fields(sandbox_id = %self.reference.id), err)]
    async fn stop(&self) -> Result<(), Error> {
        self.ensure_open()?;
        match self.state().await.map_err(not_started)? {
            LegacyState::Stopped | LegacyState::Archived => return Ok(()),
            LegacyState::Deleted => return Err(self.absent()),
            _ => {}
        }
        let stopped = LegacySandbox::stop(self.handle.as_ref()).await;
        // Success is Daytona's own report that the sandbox is stopped, read
        // after the request: an accepted stop is not a fence.
        let state = match self.state().await? {
            LegacyState::Stopped | LegacyState::Archived => return Ok(()),
            LegacyState::Deleted => return Err(self.absent()),
            state => state,
        };
        let message = match stopped.map_err(|error| classify("stopping sandbox", error)) {
            Ok(()) => format!("the sandbox is {state:?} after stop"),
            Err(error) if refused(&error) => return Err(error),
            Err(error) => error.to_string(),
        };
        Err(Error::FenceLeaked { message })
    }

    async fn exec(&self, spec: ExecSpec, controls: ExecControls) -> Result<ExecOutcome, Error> {
        spec.validate()?;
        if spec.tty {
            return Err(Error::Unsupported {
                capability: "tty".to_owned(),
            });
        }
        let ExecControls {
            stdin,
            sink,
            term,
            kill,
            resize: _,
        } = controls;
        // Admission first, so a refused command consumes none of its input.
        let mut admitted = self.admit().await?;
        let mut legacy = legacy_spec(&spec);
        let mut stdin = stdin;
        if self.nested() {
            if let Some(input) = stdin.take() {
                let timeout = spec.timeout_ms.map(Duration::from_millis);
                let read = self.nested_stdin(input, timeout, term.as_ref(), kill.as_ref());
                match read.await? {
                    Ok(bytes) => legacy.stdin = Some(bytes),
                    Err(termination) => return Ok(outcome_of(termination)),
                }
                // The read can outlast a stop and a restart. The command
                // runs only in a generation that admits it.
                admitted = self.admit().await?;
            }
        }
        let mut legacy_controls = Self::output_controls(sink, term, kill);
        legacy_controls.stdin = stdin.map(StdinSource::new);
        self.fenced(
            self.handle.exec().run_streaming(&legacy, legacy_controls),
            admitted,
        )
        .await
    }

    fn files(&self) -> &dyn Files {
        self
    }

    fn ports(&self) -> &dyn Ports {
        self
    }

    fn containers(&self) -> Option<&dyn Containers> {
        Some(self)
    }
}

#[async_trait]
impl Files for Workload {
    async fn get(&self, path: &str, range: Option<FileRange>) -> Result<ByteStream, Error> {
        self.ensure_open()?;
        let fs = self.handle.fs();
        let bytes = match range {
            Some(range) => fs.read_range(path, range.offset, range.length).await,
            None => fs.read(path).await,
        }
        .map_err(|error| classify("reading file", error))?;
        Ok(Box::pin(Cursor::new(bytes)))
    }

    async fn put(&self, path: &str, bytes: ByteStream) -> Result<(), Error> {
        // Admission first, so a refused write does not drain the caller's
        // stream. The write itself still fails if a stop wins the race.
        self.admit().await?;
        let buffer = Self::buffered(bytes, "file input").await?;
        self.handle
            .fs()
            .write(path, &buffer)
            .await
            .map_err(|error| classify("writing file", error))
    }

    async fn list(&self, path: &str, depth: u32) -> Result<Vec<FileEntry>, Error> {
        self.ensure_open()?;
        let depth = usize::try_from(depth)
            .unwrap_or(usize::MAX)
            .saturating_add(1);
        let entries = self
            .handle
            .fs()
            .list_dir(path, depth)
            .await
            .map_err(|error| classify("listing directory", error))?;
        let base =
            crate::resolve_path(LegacySandbox::working_directory(self.handle.as_ref()), path);
        Ok(entries
            .into_iter()
            .map(|entry| FileEntry {
                path: format!("{}/{}", base.trim_end_matches('/'), entry.path),
                kind: entry.kind,
                size: entry.size.unwrap_or(0),
            })
            .collect())
    }
}

#[async_trait]
impl Ports for Workload {
    async fn expose(&self, port: NonZeroU16, options: Expose) -> Result<Exposure, Error> {
        self.ensure_open()?;
        let access = self.handle.access();
        let millis = |duration: Duration| u64::try_from(duration.as_millis()).unwrap_or(u64::MAX);
        let ttl = options
            .ttl_ms
            .map_or(DEFAULT_SIGNED_TTL, Duration::from_millis);
        let preview = if options.signed {
            access.signed_preview_url(port.get(), ttl).await
        } else {
            access.preview_url(port.get()).await
        }
        .map_err(|error| classify("exposing port", error))?;
        let expires_at_ms = options.signed.then(|| {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, millis);
            now.saturating_add(millis(ttl))
        });
        Ok(Exposure {
            url: preview.url,
            headers: preview.headers,
            expires_at_ms,
        })
    }

    async fn release(&self, _port: NonZeroU16) -> Result<(), Error> {
        // Daytona preview URLs hold nothing on the caller's behalf.
        self.ensure_open()
    }
}

#[async_trait]
impl Containers for Workload {
    async fn run(&self, spec: OneShotSpec, controls: ExecControls) -> Result<ExecOutcome, Error> {
        spec.validate()?;
        let ExecControls {
            stdin,
            sink,
            term,
            kill,
            resize: _,
        } = controls;
        // The one-shot runner attaches no input; refuse rather than drop it.
        if stdin.is_some() {
            return Err(Error::Unsupported {
                capability: "containers.stdin".to_owned(),
            });
        }
        let admitted = self.admit().await?;
        if !self.has_docker().await? {
            return Err(Error::Unsupported {
                capability: "containers: the workload image provides no Docker".to_owned(),
            });
        }
        let image = match spec.image {
            OneShotImage::Image(reference) => LegacyImage::Registry { reference },
            OneShotImage::Build {
                context,
                dockerfile,
                tag,
                reuse,
            } => LegacyImage::Build {
                context,
                dockerfile,
                tag,
                reuse,
            },
        };
        let mut legacy = LegacyOneShot::new(image);
        legacy.entrypoint = spec.entrypoint;
        legacy.args = spec.args;
        legacy.env = spec.env;
        legacy.working_dir = spec.working_directory;
        legacy.timeout = spec.timeout_ms.map(Duration::from_millis);
        let controls = Self::output_controls(sink, term, kill);
        let one_shot = self.handle.one_shot().ok_or_else(|| Error::Unsupported {
            capability: "containers".to_owned(),
        })?;
        self.fenced(one_shot.run(&legacy, controls), admitted).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transitions_that_keep_the_workload_usable_read_as_running() {
        assert_eq!(
            contract_state(LegacyState::Snapshotting),
            SandboxState::Running
        );
        assert_eq!(
            contract_state(LegacyState::Stopping),
            SandboxState::Stopping
        );
        assert_eq!(contract_state(LegacyState::Error), SandboxState::Unhealthy);
        assert_eq!(contract_state(LegacyState::Unknown), SandboxState::Unknown);
    }

    #[test]
    fn provider_metadata_never_reaches_caller_labels() {
        let labels = HashMap::from([
            ("sh.sandbox-driver.recipe".to_owned(), "nested".to_owned()),
            ("sh.sandbox-driver.managed".to_owned(), "true".to_owned()),
            ("job".to_owned(), "quotes='\" λ\n".to_owned()),
        ]);
        assert_eq!(
            public_labels(&labels),
            BTreeMap::from([("job".to_owned(), "quotes='\" λ\n".to_owned())])
        );
    }

    #[test]
    fn exec_maps_argv_and_an_absent_timeout_to_no_timeout() {
        let mut spec = ExecSpec::argv(["make", "test"]);
        spec.working_directory = Some("sub".to_owned());
        let legacy = legacy_spec(&spec);
        assert_eq!(legacy.program, "make");
        assert_eq!(legacy.args, vec!["test".to_owned()]);
        assert_eq!(legacy.timeout, None);
        assert_eq!(legacy.working_dir.as_deref(), Some("sub"));
        spec.timeout_ms = Some(1500);
        assert_eq!(
            legacy_spec(&spec).timeout,
            Some(Duration::from_millis(1500))
        );
    }
}
