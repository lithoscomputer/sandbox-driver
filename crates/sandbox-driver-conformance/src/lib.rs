//! Black-box conformance suite for sandbox-driver providers.
//!
//! Runs the same end-to-end battery against any [`SandboxProvider`] —
//! in-process or behind the JSON-RPC protocol — and reports per-check
//! outcomes. Checks are **capability-gated in both directions**: a
//! declared capability must work, and an undeclared one must return
//! [`Error::Unsupported`]. That is the capability-honesty contract from
//! the design.
//!
//! ```ignore
//! let report = Conformance::new(provider, SpecFactory::new(make_spec))
//!     .run()
//!     .await;
//! report.assert_pass();
//! ```
//!
//! Each check provisions its own sandbox from the provider-appropriate
//! spec the factory returns and deletes it afterwards, so the suite is
//! safe to run against real (billed) providers — expect roughly three dozen
//! short-lived sandboxes per run.

use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use std::{fmt, process};

use async_trait::async_trait;
use sandbox_driver::{
    Action, Capability, DerivedSearch, DerivedServices, Error, Event, EventBody, EventContext,
    EventObserver, ExecControls, ExecSpec, GrepOptions, HealthStatus, LogSink, LogSource,
    NetworkPolicy, OutputSanitization, OutputStream, PtyOptions, PtySize, Resources, Sandbox,
    SandboxFilter, SandboxId, SandboxProvider, SandboxSpec, SandboxState, Search, ServiceSpec,
    Services, SnapshotMode, SpawnSpec, Termination, WaitOptions, activate, wait_for_state,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time;
use tokio_util::sync::CancellationToken;

type SeenChunks = Arc<Mutex<Vec<(OutputStream, Vec<u8>)>>>;

#[derive(Default)]
struct RecordingEventObserver {
    events: Mutex<Vec<Event>>,
}

#[async_trait]
impl EventObserver for RecordingEventObserver {
    async fn observe(&self, event: Event) {
        self.events.lock().expect("events lock").push(event);
    }
}

/// Produces a provider-appropriate creation spec for each check.
pub struct SpecFactory {
    make:                 Box<dyn Fn() -> SandboxSpec + Send + Sync>,
    make_entrypoint_logs: Option<Box<dyn Fn() -> SandboxSpec + Send + Sync>>,
}

impl SpecFactory {
    pub fn new(make: impl Fn() -> SandboxSpec + Send + Sync + 'static) -> Self {
        Self {
            make:                 Box::new(make),
            make_entrypoint_logs: None,
        }
    }

    /// Adds a spec whose entrypoint emits output and remains running.
    /// Providers that declare [`sandbox_driver::Logs`] use this fixture
    /// for the behavioral follow-stream check.
    #[must_use]
    pub fn with_entrypoint_logs(
        mut self,
        make: impl Fn() -> SandboxSpec + Send + Sync + 'static,
    ) -> Self {
        self.make_entrypoint_logs = Some(Box::new(make));
        self
    }

    fn spec(&self) -> SandboxSpec {
        (self.make)()
    }

    fn entrypoint_logs_spec(&self) -> Option<SandboxSpec> {
        self.make_entrypoint_logs.as_ref().map(|make| make())
    }
}

/// Suite configuration.
pub struct Conformance {
    provider:          Arc<dyn SandboxProvider>,
    specs:             SpecFactory,
    /// Per-check wall-clock budget; a hung provider fails, not hangs.
    pub check_timeout: Duration,
    /// Wait options for state transitions (slow cloud providers need a
    /// longer deadline).
    pub wait:          WaitOptions,
}

impl Conformance {
    pub fn new(provider: Arc<dyn SandboxProvider>, specs: SpecFactory) -> Self {
        Self {
            provider,
            specs,
            check_timeout: Duration::from_secs(300),
            wait: WaitOptions {
                interval: Duration::from_secs(1),
                deadline: Some(Duration::from_secs(120)),
            },
        }
    }

    /// Runs the whole battery.
    pub async fn run(&self) -> Report {
        let checks: &[(&'static str, CheckFn)] = &[
            ("provider_identity_and_list", |ctx| {
                Box::pin(provider_identity_and_list(ctx))
            }),
            ("create_describe_delete", |ctx| {
                Box::pin(create_describe_delete(ctx))
            }),
            ("delete_is_idempotent", |ctx| {
                Box::pin(delete_is_idempotent(ctx))
            }),
            ("attach_unknown_id_is_not_found", |ctx| {
                Box::pin(attach_unknown_id_is_not_found(ctx))
            }),
            ("activate_passes_bash_probe", |ctx| {
                Box::pin(activate_passes_bash_probe(ctx))
            }),
            ("working_directory_is_effective", |ctx| {
                Box::pin(working_directory_is_effective(ctx))
            }),
            ("runtime_directory_is_private", |ctx| {
                Box::pin(runtime_directory_is_private(ctx))
            }),
            ("relative_working_dir_resolves", |ctx| {
                Box::pin(relative_working_dir_resolves(ctx))
            }),
            ("exec_reports_exit_codes", |ctx| {
                Box::pin(exec_reports_exit_codes(ctx))
            }),
            ("exec_env_vars_apply", |ctx| {
                Box::pin(exec_env_vars_apply(ctx))
            }),
            ("exec_output_is_binary_safe", |ctx| {
                Box::pin(exec_output_is_binary_safe(ctx))
            }),
            ("exec_output_sanitization_is_consistent", |ctx| {
                Box::pin(exec_output_sanitization_is_consistent(ctx))
            }),
            ("exec_stdin_round_trips", |ctx| {
                Box::pin(exec_stdin_round_trips(ctx))
            }),
            ("exec_timeout_terminates", |ctx| {
                Box::pin(exec_timeout_terminates(ctx))
            }),
            ("exec_cancel_terminates", |ctx| {
                Box::pin(exec_cancel_terminates(ctx))
            }),
            ("exec_streaming_is_honest", |ctx| {
                Box::pin(exec_streaming_is_honest(ctx))
            }),
            ("exec_retention_accounting_is_consistent", |ctx| {
                Box::pin(exec_retention_accounting_is_consistent(ctx))
            }),
            ("concurrent_streams_do_not_starve_each_other", |ctx| {
                Box::pin(concurrent_streams_do_not_starve_each_other(ctx))
            }),
            ("fs_round_trips", |ctx| Box::pin(fs_round_trips(ctx))),
            ("search_greps_directories_and_single_files", |ctx| {
                Box::pin(search_greps_directories_and_single_files(ctx))
            }),
            ("unsupported_actions_say_so", |ctx| {
                Box::pin(unsupported_actions_say_so(ctx))
            }),
            ("pause_resume_cycle", |ctx| {
                Box::pin(pause_resume_cycle(ctx))
            }),
            ("fork_preserves_live_process_state", |ctx| {
                Box::pin(fork_preserves_live_process_state(ctx))
            }),
            ("snapshot_modes_are_honest", |ctx| {
                Box::pin(snapshot_modes_are_honest(ctx))
            }),
            ("stdio_process_round_trips", |ctx| {
                Box::pin(stdio_process_round_trips(ctx))
            }),
            ("pty_is_bidirectional", |ctx| {
                Box::pin(pty_is_bidirectional(ctx))
            }),
            ("logs_follow_streams_and_cancels", |ctx| {
                Box::pin(logs_follow_streams_and_cancels(ctx))
            }),
            ("attach_and_list_by_label", |ctx| {
                Box::pin(attach_and_list_by_label(ctx))
            }),
            ("create_emits_terminal_events", |ctx| {
                Box::pin(create_emits_terminal_events(ctx))
            }),
            ("services_match_capabilities", |ctx| {
                Box::pin(services_match_capabilities(ctx))
            }),
            ("ssh_access_matches_capabilities", |ctx| {
                Box::pin(ssh_access_matches_capabilities(ctx))
            }),
            ("shell_command_access_matches_capabilities", |ctx| {
                Box::pin(shell_command_access_matches_capabilities(ctx))
            }),
            ("exec_rejects_undeclared_stdin_and_cancel", |ctx| {
                Box::pin(exec_rejects_undeclared_stdin_and_cancel(ctx))
            }),
            ("fs_range_and_append_round_trip", |ctx| {
                Box::pin(fs_range_and_append_round_trip(ctx))
            }),
            ("background_services_round_trip", |ctx| {
                Box::pin(background_services_round_trip(ctx))
            }),
            ("provider_health_answers", |ctx| {
                Box::pin(provider_health_answers(ctx))
            }),
            ("volume_round_trip", |ctx| Box::pin(volume_round_trip(ctx))),
        ];

        let mut results = Vec::new();
        for (name, check) in checks {
            let outcome = match time::timeout(self.check_timeout, check(self)).await {
                Ok(Ok(None)) => Outcome::Passed,
                Ok(Ok(Some(reason))) => Outcome::Skipped { reason },
                Ok(Err(reason)) => Outcome::Failed { reason },
                Err(_) => Outcome::Failed {
                    reason: format!("check exceeded the {:?} budget", self.check_timeout),
                },
            };
            results.push(CheckResult { name, outcome });
        }
        Report { results }
    }

    async fn create(&self) -> Result<Arc<dyn Sandbox>, String> {
        self.provider
            .create(&self.specs.spec(), None)
            .await
            .map_err(|error| format!("create failed: {error}"))
    }

    async fn ready(&self) -> Result<Arc<dyn Sandbox>, String> {
        let spec = self.specs.spec();
        self.ready_from_spec(&spec).await
    }

    async fn ready_from_spec(&self, spec: &SandboxSpec) -> Result<Arc<dyn Sandbox>, String> {
        let sandbox = self
            .provider
            .create(spec, None)
            .await
            .map_err(|error| format!("create failed: {error}"))?;
        if let Err(error) = activate(sandbox.as_ref(), &self.wait).await {
            let _ = sandbox.delete().await;
            return Err(format!("activate failed: {error}"));
        }
        Ok(sandbox)
    }

    fn caps(&self) -> &sandbox_driver::Capabilities {
        self.provider.capabilities()
    }
}

type CheckFn =
    fn(&Conformance) -> Pin<Box<dyn Future<Output = Result<Option<String>, String>> + Send + '_>>;

/// `Ok(None)` = passed, `Ok(Some(reason))` = skipped, `Err` = failed.
type CheckOutcome = Result<Option<String>, String>;

/// Outcome of one check.
#[derive(Clone, Debug)]
pub enum Outcome {
    Passed,
    Skipped { reason: String },
    Failed { reason: String },
}

/// One line of the report.
#[derive(Clone, Debug)]
pub struct CheckResult {
    pub name:    &'static str,
    pub outcome: Outcome,
}

/// The suite's result.
#[derive(Clone, Debug)]
pub struct Report {
    pub results: Vec<CheckResult>,
}

impl Report {
    pub fn failures(&self) -> Vec<&CheckResult> {
        self.results
            .iter()
            .filter(|result| matches!(result.outcome, Outcome::Failed { .. }))
            .collect()
    }

    /// Panics with the full report when any check failed.
    pub fn assert_pass(&self) {
        assert!(self.failures().is_empty(), "conformance failures:\n{self}");
    }
}

impl fmt::Display for Report {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for result in &self.results {
            match &result.outcome {
                Outcome::Passed => writeln!(f, "PASS {}", result.name)?,
                Outcome::Skipped { reason } => {
                    writeln!(f, "SKIP {} ({reason})", result.name)?;
                }
                Outcome::Failed { reason } => writeln!(f, "FAIL {}: {reason}", result.name)?,
            }
        }
        Ok(())
    }
}

fn fail(message: impl Into<String>) -> CheckOutcome {
    Err(message.into())
}

const PASS: CheckOutcome = Ok(None);

async fn cleanup(sandbox: &Arc<dyn Sandbox>) {
    let _ = sandbox.delete().await;
}

// --- Checks ---

async fn provider_identity_and_list(ctx: &Conformance) -> CheckOutcome {
    if ctx.provider.kind().as_str().is_empty() {
        return fail("provider kind is empty");
    }
    ctx.provider
        .list(&SandboxFilter::default())
        .await
        .map_err(|error| format!("list failed: {error}"))?;
    if let Some(snapshots) = &ctx.provider.capabilities().snapshots {
        if (snapshots.from_image_kinds.container || snapshots.from_image_kinds.virtual_machine)
            && !snapshots.from_image
        {
            return fail("exact image snapshot support is set but aggregate support is false");
        }
        if (snapshots.from_dockerfile_kinds.container
            || snapshots.from_dockerfile_kinds.virtual_machine)
            && !snapshots.from_dockerfile
        {
            return fail("exact Dockerfile snapshot support is set but aggregate support is false");
        }
    }
    PASS
}

async fn create_describe_delete(ctx: &Conformance) -> CheckOutcome {
    let mut spec = ctx.specs.spec();
    if spec.name.is_none() {
        spec.name = Some(format!("sandbox-driver-conformance-{}", process::id()));
    }
    let sandbox = ctx
        .provider
        .create(&spec, None)
        .await
        .map_err(|error| format!("create failed: {error}"))?;
    let outcome = async {
        let status = sandbox
            .describe()
            .await
            .map_err(|error| format!("describe failed: {error}"))?;
        if status.id != *sandbox.id() {
            return fail("describe returned a different sandbox id");
        }
        if status.name != spec.name {
            return fail(format!(
                "requested display name {:?}, observed {:?}",
                spec.name, status.name
            ));
        }
        if let Some(requested) = spec.sandbox_kind {
            if status.sandbox_kind != Some(requested) {
                return fail(format!(
                    "requested sandbox kind {requested:?}, observed {:?}",
                    status.sandbox_kind
                ));
            }
        }
        if let Some(requested) = &spec.region {
            if status.region.as_deref() != Some(requested) {
                return fail(format!(
                    "requested region {requested:?}, observed {:?}",
                    status.region
                ));
            }
        }
        if sandbox.working_directory().is_empty() {
            return fail("working_directory is empty");
        }
        let platform = sandbox
            .platform_info()
            .await
            .map_err(|error| format!("platform_info failed: {error}"))?;
        if platform.os.is_empty() || platform.os != platform.os.to_lowercase() {
            return fail(format!("platform os {:?} is not lowercase", platform.os));
        }
        // A kernel release ("6.8.0-…") in the arch field is the classic
        // uname field-order mixup; real architectures have no dots.
        if platform.arch.is_empty() || platform.arch.contains('.') {
            return fail(format!(
                "platform arch {:?} does not look like an architecture",
                platform.arch
            ));
        }
        PASS
    }
    .await;
    cleanup(&sandbox).await;
    outcome?;

    let sandbox_id = sandbox.id().clone();
    // After delete, describe (via re-attach) must not report a live sandbox.
    match ctx.provider.attach(&sandbox_id, None).await {
        Err(_) => PASS,
        Ok(handle) => {
            let state = handle
                .describe()
                .await
                .map_or(SandboxState::Deleted, |status| status.state);
            if matches!(state, SandboxState::Deleted | SandboxState::Deleting) {
                PASS
            } else {
                fail(format!("sandbox still {state:?} after delete"))
            }
        }
    }
}

async fn delete_is_idempotent(ctx: &Conformance) -> CheckOutcome {
    let sandbox = ctx.create().await?;
    sandbox
        .delete()
        .await
        .map_err(|error| format!("first delete failed: {error}"))?;
    sandbox
        .delete()
        .await
        .map_err(|error| format!("second delete failed: {error}"))?;
    PASS
}

async fn attach_unknown_id_is_not_found(ctx: &Conformance) -> CheckOutcome {
    let id = SandboxId::try_new("conformance-does-not-exist").map_err(|error| error.to_string())?;
    match ctx.provider.attach(&id, None).await {
        Err(Error::NotFound { .. }) => PASS,
        Err(other) => fail(format!("expected NotFound, got: {other}")),
        Ok(_) => fail("attach to an unknown id succeeded"),
    }
}

async fn activate_passes_bash_probe(ctx: &Conformance) -> CheckOutcome {
    let sandbox = ctx.ready().await?;
    cleanup(&sandbox).await;
    PASS
}

async fn working_directory_is_effective(ctx: &Conformance) -> CheckOutcome {
    let spec = ctx.specs.spec();
    let requested = spec.working_directory.clone();
    let sandbox = ctx.ready_from_spec(&spec).await?;
    let outcome = async {
        if let Some(requested) = &requested {
            if sandbox.working_directory() != requested {
                return fail(format!(
                    "requested working_directory {requested:?}, handle returned {:?}",
                    sandbox.working_directory()
                ));
            }
        }
        let result = sandbox
            .exec()
            .run(&ExecSpec::new("pwd").timeout(Duration::from_secs(30)))
            .await
            .map_err(|error| format!("exec failed: {error}"))?;
        let pwd = result.stdout_lossy().trim().to_owned();
        let expected = sandbox.working_directory();
        if pwd != expected {
            return fail(format!("pwd is {pwd:?}, working_directory is {expected:?}"));
        }
        let attached = ctx
            .provider
            .attach(sandbox.id(), None)
            .await
            .map_err(|error| format!("attach failed: {error}"))?;
        if attached.working_directory() != expected {
            return fail(format!(
                "attached working_directory is {:?}, expected {expected:?}",
                attached.working_directory()
            ));
        }
        let attached_result = attached
            .exec()
            .run(&ExecSpec::new("pwd").timeout(Duration::from_secs(30)))
            .await
            .map_err(|error| format!("attached exec failed: {error}"))?;
        let attached_pwd = attached_result.stdout_lossy().trim().to_owned();
        if attached_pwd != expected {
            return fail(format!(
                "attached pwd is {attached_pwd:?}, working_directory is {expected:?}"
            ));
        }
        PASS
    }
    .await;
    cleanup(&sandbox).await;
    outcome
}

async fn runtime_directory_is_private(ctx: &Conformance) -> CheckOutcome {
    let sandbox = ctx.ready().await?;
    let outcome = async {
        let Some(runtime_directory) = sandbox.runtime_directory() else {
            return PASS;
        };
        if !runtime_directory.starts_with('/') {
            return fail(format!(
                "runtime_directory {runtime_directory:?} is not absolute"
            ));
        }
        let workspace = sandbox.working_directory().trim_end_matches('/');
        let workspace_prefix = if workspace.is_empty() {
            "/".to_owned()
        } else {
            format!("{workspace}/")
        };
        if runtime_directory == workspace || runtime_directory.starts_with(&workspace_prefix) {
            return fail(format!(
                "runtime_directory {runtime_directory:?} is inside working_directory \
                 {workspace:?}"
            ));
        }
        let metadata = sandbox
            .fs()
            .metadata(runtime_directory)
            .await
            .map_err(|error| format!("runtime_directory metadata failed: {error}"))?;
        if metadata.kind != sandbox_driver::FileKind::Directory {
            return fail(format!(
                "runtime_directory has kind {:?}, not Directory",
                metadata.kind
            ));
        }
        if metadata.mode.map(|mode| mode & 0o777) != Some(0o700) {
            return fail(format!(
                "runtime_directory mode is {:?}, expected 0700",
                metadata.mode
            ));
        }
        let attached = ctx
            .provider
            .attach(sandbox.id(), None)
            .await
            .map_err(|error| format!("attach failed: {error}"))?;
        if attached.runtime_directory() != Some(runtime_directory) {
            return fail(format!(
                "attached runtime_directory is {:?}, expected {runtime_directory:?}",
                attached.runtime_directory()
            ));
        }
        PASS
    }
    .await;
    cleanup(&sandbox).await;
    outcome
}

/// A relative exec `working_dir` resolves against the sandbox working
/// directory on every provider.
async fn relative_working_dir_resolves(ctx: &Conformance) -> CheckOutcome {
    let sandbox = ctx.ready().await?;
    let outcome = async {
        let mkdir = sandbox
            .exec()
            .run(&ExecSpec::new("mkdir -p cwd-probe").timeout(Duration::from_secs(30)))
            .await
            .map_err(|error| format!("mkdir failed: {error}"))?;
        if !mkdir.success() {
            return fail(format!("mkdir failed: {}", mkdir.stderr_lossy()));
        }
        let result = sandbox
            .exec()
            .run(
                &ExecSpec::new("pwd")
                    .working_dir("cwd-probe")
                    .timeout(Duration::from_secs(30)),
            )
            .await
            .map_err(|error| format!("exec failed: {error}"))?;
        let pwd = result.stdout_lossy().trim().to_owned();
        let expected = format!(
            "{}/cwd-probe",
            sandbox.working_directory().trim_end_matches('/')
        );
        if pwd != expected {
            return fail(format!("pwd is {pwd:?}, expected {expected:?}"));
        }
        PASS
    }
    .await;
    cleanup(&sandbox).await;
    outcome
}

async fn exec_reports_exit_codes(ctx: &Conformance) -> CheckOutcome {
    let sandbox = ctx.ready().await?;
    let outcome = async {
        let result = sandbox
            .exec()
            .run(&ExecSpec::new("exit 7").timeout(Duration::from_secs(30)))
            .await
            .map_err(|error| format!("exec failed: {error}"))?;
        if result.exit_code != Some(7) {
            return fail(format!("expected exit code 7, got {:?}", result.exit_code));
        }
        if result.termination != Termination::Exited {
            return fail(format!("expected Exited, got {:?}", result.termination));
        }
        PASS
    }
    .await;
    cleanup(&sandbox).await;
    outcome
}

async fn exec_env_vars_apply(ctx: &Conformance) -> CheckOutcome {
    let sandbox = ctx.ready().await?;
    let outcome = async {
        let spec = ExecSpec::new("printf '%s' \"$CONFORMANCE_VALUE\"")
            .env_var("CONFORMANCE_VALUE", "expected-value")
            .timeout(Duration::from_secs(30));
        let result = sandbox
            .exec()
            .run(&spec)
            .await
            .map_err(|error| format!("exec failed: {error}"))?;
        if result.stdout_lossy() != "expected-value" {
            return fail(format!(
                "environment variable missing: {:?}",
                result.stdout_lossy()
            ));
        }
        PASS
    }
    .await;
    cleanup(&sandbox).await;
    outcome
}

async fn exec_output_is_binary_safe(ctx: &Conformance) -> CheckOutcome {
    let sandbox = ctx.ready().await?;
    let outcome = async {
        let spec = ExecSpec::new("printf 'a\\0b\\x01c'").timeout(Duration::from_secs(30));
        let result = sandbox
            .exec()
            .run(&spec)
            .await
            .map_err(|error| format!("exec failed: {error}"))?;
        if result.stdout != b"a\0b\x01c" {
            return fail(format!("binary output mangled: {:?}", result.stdout));
        }
        PASS
    }
    .await;
    cleanup(&sandbox).await;
    outcome
}

async fn exec_output_sanitization_is_consistent(ctx: &Conformance) -> CheckOutcome {
    let sandbox = ctx.ready().await?;
    let outcome = async {
        let command = "printf '\\033[31mred\\033[0m\\007\\001\\n'";

        let raw = sandbox
            .exec()
            .run(&ExecSpec::new(command))
            .await
            .map_err(|error| format!("raw exec failed: {error}"))?;
        if raw.stdout != b"\x1b[31mred\x1b[0m\x07\x01\n" {
            return fail(format!("raw output changed: {:?}", raw.stdout));
        }

        let ansi = sandbox
            .exec()
            .run(&ExecSpec::new(command).output_sanitization(OutputSanitization::StripAnsi))
            .await
            .map_err(|error| format!("StripAnsi exec failed: {error}"))?;
        if ansi.stdout != b"red\x07\x01\n" {
            return fail(format!(
                "StripAnsi returned wrong output: {:?}",
                ansi.stdout
            ));
        }

        let chunks: SeenChunks = Arc::new(Mutex::new(Vec::new()));
        let sink_chunks = Arc::clone(&chunks);
        let controls = ExecControls {
            sink: Some(Arc::new(move |stream, chunk| {
                let chunks = Arc::clone(&sink_chunks);
                Box::pin(async move {
                    chunks.lock().expect("chunks lock").push((stream, chunk));
                    Ok(())
                })
            })),
            ..ExecControls::default()
        };
        let spec =
            ExecSpec::new("printf '\\033'; sleep 0.05; printf '[31mred\\033[0m\\007\\001\\n'")
                .output_sanitization(OutputSanitization::StripAll)
                .timeout(Duration::from_secs(30));
        let all = sandbox
            .exec()
            .run_streaming(&spec, controls)
            .await
            .map_err(|error| format!("StripAll streaming exec failed: {error}"))?;
        if !all.result.success() {
            return fail(format!(
                "StripAll streaming command failed: {}",
                all.result.stderr_lossy()
            ));
        }
        if all.result.stdout != b"red\n" {
            return fail(format!(
                "StripAll returned wrong output: {:?}",
                all.result.stdout
            ));
        }
        let streamed: Vec<u8> = chunks
            .lock()
            .expect("chunks lock")
            .iter()
            .flat_map(|(_, chunk)| chunk.clone())
            .collect();
        if streamed != b"red\n" {
            return fail(format!("StripAll sink saw wrong output: {streamed:?}"));
        }
        if all.stdout_capture.observed_bytes != b"red\n".len() {
            return fail(format!(
                "capture stats counted pre-sanitization bytes: {:?}",
                all.stdout_capture
            ));
        }
        PASS
    }
    .await;
    cleanup(&sandbox).await;
    outcome
}

async fn exec_stdin_round_trips(ctx: &Conformance) -> CheckOutcome {
    if !ctx.caps().exec.stdin {
        return Ok(Some("capability exec.stdin not declared".to_owned()));
    }
    let sandbox = ctx.ready().await?;
    let outcome = async {
        let spec = ExecSpec::new("cat")
            .stdin(b"stdin-payload".to_vec())
            .timeout(Duration::from_secs(30));
        let result = sandbox
            .exec()
            .run(&spec)
            .await
            .map_err(|error| format!("exec failed: {error}"))?;
        if result.stdout != b"stdin-payload" {
            return fail(format!("stdin not delivered: {:?}", result.stdout_lossy()));
        }
        PASS
    }
    .await;
    cleanup(&sandbox).await;
    outcome
}

async fn exec_timeout_terminates(ctx: &Conformance) -> CheckOutcome {
    let sandbox = ctx.ready().await?;
    let outcome = async {
        let started = Instant::now();
        let spec = ExecSpec::new("sleep 300").timeout(Duration::from_secs(2));
        let result = sandbox
            .exec()
            .run(&spec)
            .await
            .map_err(|error| format!("exec failed: {error}"))?;
        if result.termination != Termination::TimedOut {
            return fail(format!("expected TimedOut, got {:?}", result.termination));
        }
        if started.elapsed() > Duration::from_secs(60) {
            return fail("timeout enforcement took over a minute");
        }
        PASS
    }
    .await;
    cleanup(&sandbox).await;
    outcome
}

async fn exec_cancel_terminates(ctx: &Conformance) -> CheckOutcome {
    if !ctx.caps().exec.cancel {
        return Ok(Some("capability exec.cancel not declared".to_owned()));
    }
    let sandbox = ctx.ready().await?;
    let outcome = async {
        let token = CancellationToken::new();
        let cancel_after = token.clone();
        tokio::spawn(async move {
            time::sleep(Duration::from_millis(500)).await;
            cancel_after.cancel();
        });
        let controls = ExecControls {
            cancel: Some(token),
            ..ExecControls::default()
        };
        let streaming = sandbox
            .exec()
            .run_streaming(&ExecSpec::new("sleep 300"), controls)
            .await
            .map_err(|error| format!("exec failed: {error}"))?;
        if streaming.result.termination != Termination::Cancelled {
            return fail(format!(
                "expected Cancelled, got {:?}",
                streaming.result.termination
            ));
        }
        PASS
    }
    .await;
    cleanup(&sandbox).await;
    outcome
}

async fn exec_streaming_is_honest(ctx: &Conformance) -> CheckOutcome {
    let sandbox = ctx.ready().await?;
    let outcome = async {
        let chunks: SeenChunks = Arc::new(Mutex::new(Vec::new()));
        let sink_chunks = Arc::clone(&chunks);
        let controls = ExecControls {
            sink: Some(Arc::new(move |stream, chunk| {
                let chunks = Arc::clone(&sink_chunks);
                Box::pin(async move {
                    chunks.lock().expect("chunks lock").push((stream, chunk));
                    Ok(())
                })
            })),
            ..ExecControls::default()
        };
        let spec =
            ExecSpec::new("echo to-stdout; echo to-stderr >&2").timeout(Duration::from_secs(30));
        let streaming = sandbox
            .exec()
            .run_streaming(&spec, controls)
            .await
            .map_err(|error| format!("exec failed: {error}"))?;
        if !streaming.result.success() {
            return fail(format!(
                "command failed: {}",
                streaming.result.stderr_lossy()
            ));
        }

        let caps = ctx.caps();
        if streaming.live_streaming && !caps.exec.live_streaming {
            return fail("result claims live_streaming but the capability is not declared");
        }
        if streaming.streams_separated && !caps.exec.streams_separated {
            return fail("result claims streams_separated but the capability is not declared");
        }

        let seen = chunks.lock().expect("chunks lock").clone();
        let all: Vec<u8> = seen.iter().flat_map(|(_, chunk)| chunk.clone()).collect();
        let text = String::from_utf8_lossy(&all);
        if !text.contains("to-stdout") {
            return fail("sink never saw stdout output");
        }
        if streaming.streams_separated {
            let stderr: Vec<u8> = seen
                .iter()
                .filter(|(stream, _)| *stream == OutputStream::Stderr)
                .flat_map(|(_, chunk)| chunk.clone())
                .collect();
            if !String::from_utf8_lossy(&stderr).contains("to-stderr") {
                return fail("streams_separated is set but stderr never arrived on stderr");
            }
        }
        PASS
    }
    .await;
    cleanup(&sandbox).await;
    outcome
}

async fn exec_retention_accounting_is_consistent(ctx: &Conformance) -> CheckOutcome {
    let sandbox = ctx.ready().await?;
    let outcome = async {
        let controls = ExecControls {
            retained_output_limit: Some(512),
            ..ExecControls::default()
        };
        let spec = ExecSpec::new("for i in $(seq 1 500); do echo payload-line-$i; done")
            .timeout(Duration::from_secs(60));
        let streaming = sandbox
            .exec()
            .run_streaming(&spec, controls)
            .await
            .map_err(|error| format!("exec failed: {error}"))?;
        let stats = streaming.stdout_capture;
        if stats.observed_bytes > 0
            && stats.retained_bytes + stats.omitted_bytes != stats.observed_bytes
        {
            return fail(format!("capture accounting inconsistent: {stats:?}"));
        }
        if stats.observed_bytes > 0 && streaming.result.stdout.len() > 512 {
            return fail(format!(
                "retained output exceeds the cap: {} bytes",
                streaming.result.stdout.len()
            ));
        }
        PASS
    }
    .await;
    cleanup(&sandbox).await;
    outcome
}

/// One slow consumer of one stream must not stall other execs on the
/// same sandbox: while a deliberately slow sink drains a steady stream,
/// a second exec and a `describe` must both complete promptly, and each
/// sink must see only its own exec's output, in order.
async fn concurrent_streams_do_not_starve_each_other(ctx: &Conformance) -> CheckOutcome {
    if !ctx.caps().exec.live_streaming {
        return Ok(Some(
            "capability exec.live_streaming not declared".to_owned(),
        ));
    }
    let sandbox = ctx.ready().await?;
    let outcome = async {
        // Slow stream: a line every 50ms, consumed at 600ms/chunk, so a
        // shared-pipe client accumulates a deep backlog quickly.
        let slow_chunks: SeenChunks = Arc::new(Mutex::new(Vec::new()));
        let slow_sink_chunks = Arc::clone(&slow_chunks);
        let slow_controls = ExecControls {
            sink: Some(Arc::new(move |stream, chunk| {
                let chunks = Arc::clone(&slow_sink_chunks);
                Box::pin(async move {
                    time::sleep(Duration::from_millis(600)).await;
                    chunks.lock().expect("chunks lock").push((stream, chunk));
                    Ok(())
                })
            })),
            ..ExecControls::default()
        };
        let slow_spec = ExecSpec::new("for i in $(seq 1 20); do echo slow-$i; sleep 0.05; done")
            .timeout(Duration::from_secs(60));
        let slow_exec = sandbox.exec();
        let mut slow_task = std::pin::pin!(slow_exec.run_streaming(&slow_spec, slow_controls));
        let mut slow_done = None;

        // Let the slow stream start producing before racing it.
        tokio::select! {
            outcome = &mut slow_task => {
                slow_done = Some(outcome);
            }
            () = time::sleep(Duration::from_millis(700)) => {}
        }
        if slow_done.is_some() {
            return fail("slow exec finished before the race began".to_owned());
        }

        // Fast exec with its own sink, plus a describe, both timed.
        let fast_chunks: SeenChunks = Arc::new(Mutex::new(Vec::new()));
        let fast_sink_chunks = Arc::clone(&fast_chunks);
        let fast_controls = ExecControls {
            sink: Some(Arc::new(move |stream, chunk| {
                let chunks = Arc::clone(&fast_sink_chunks);
                Box::pin(async move {
                    chunks.lock().expect("chunks lock").push((stream, chunk));
                    Ok(())
                })
            })),
            ..ExecControls::default()
        };
        let fast_spec = ExecSpec::new("echo fast-done").timeout(Duration::from_secs(30));
        let race_started = Instant::now();
        let mut fast_and_describe = std::pin::pin!(async {
            tokio::join!(
                sandbox.exec().run_streaming(&fast_spec, fast_controls),
                sandbox.describe(),
            )
        });
        // Race the fast pair against the still-flowing slow stream,
        // continuing to poll the slow stream so its chunks keep moving.
        let (fast, described) = loop {
            tokio::select! {
                outcome = &mut fast_and_describe => break outcome,
                slow = &mut slow_task, if slow_done.is_none() => {
                    slow_done = Some(slow);
                }
            }
        };
        let raced = race_started.elapsed();
        let fast = fast.map_err(|error| format!("fast exec failed: {error}"))?;
        described.map_err(|error| format!("describe during streaming failed: {error}"))?;
        if !fast.result.success() {
            return fail("fast exec did not succeed".to_owned());
        }
        if raced > Duration::from_secs(4) {
            return fail(format!(
                "a slow consumer starved concurrent calls: fast exec + describe took {raced:?}"
            ));
        }

        // Cross-contamination and ordering.
        let fast_seen: Vec<u8> = fast_chunks
            .lock()
            .expect("chunks lock")
            .iter()
            .flat_map(|(_, chunk)| chunk.clone())
            .collect();
        let fast_text = String::from_utf8_lossy(&fast_seen);
        if !fast_text.contains("fast-done") || fast_text.contains("slow-") {
            return fail(format!("fast sink saw wrong output: {fast_text:?}"));
        }

        // Drain the slow exec to completion and verify its stream.
        let slow = match slow_done {
            Some(slow) => slow,
            None => slow_task.await,
        }
        .map_err(|error| format!("slow exec failed: {error}"))?;
        if !slow.result.success() {
            return fail("slow exec did not succeed".to_owned());
        }
        let slow_seen: Vec<u8> = slow_chunks
            .lock()
            .expect("chunks lock")
            .iter()
            .flat_map(|(_, chunk)| chunk.clone())
            .collect();
        let slow_text = String::from_utf8_lossy(&slow_seen);
        if slow_text.contains("fast-done") {
            return fail("slow sink saw the fast exec's output".to_owned());
        }
        let mut last = 0u32;
        for line in slow_text.lines().filter(|line| line.starts_with("slow-")) {
            let Ok(number) = line.trim_start_matches("slow-").parse::<u32>() else {
                continue;
            };
            if number <= last {
                return fail(format!("slow stream out of order at {line}"));
            }
            last = number;
        }
        if last != 20 {
            return fail(format!("slow stream incomplete: last line slow-{last}"));
        }
        Ok(None)
    }
    .await;
    cleanup(&sandbox).await;
    outcome
}

async fn fs_round_trips(ctx: &Conformance) -> CheckOutcome {
    let sandbox = ctx.ready().await?;
    let outcome = async {
        let fs = sandbox.fs();
        let payload = [0u8, 1, 2, 255, 254, 253];
        fs.write("conformance/dir/file.bin", &payload)
            .await
            .map_err(|error| format!("write failed: {error}"))?;
        let read = fs
            .read("conformance/dir/file.bin")
            .await
            .map_err(|error| format!("read failed: {error}"))?;
        if read != payload {
            return fail(format!("read returned different bytes: {read:?}"));
        }
        if !fs
            .exists("conformance/dir/file.bin")
            .await
            .map_err(|error| format!("exists failed: {error}"))?
        {
            return fail("exists returned false for a written file");
        }
        // A multi-hundred-KB write spans several chunks on exec-derived
        // filesystems and would overflow a single command argument if
        // sent whole (Linux caps one execve argument at 128KiB).
        let large: Vec<u8> = (0..300 * 1024)
            .map(|index: usize| u8::try_from(index % 251).expect("< 256"))
            .collect();
        fs.write("conformance/dir/large.bin", &large)
            .await
            .map_err(|error| format!("large write failed: {error}"))?;
        let read = fs
            .read("conformance/dir/large.bin")
            .await
            .map_err(|error| format!("large read failed: {error}"))?;
        if read != large {
            return fail(format!(
                "large write round trip returned {} bytes, expected {}",
                read.len(),
                large.len()
            ));
        }
        let metadata = fs
            .metadata("conformance/dir/file.bin")
            .await
            .map_err(|error| format!("metadata failed: {error}"))?;
        if metadata.size != payload.len() as u64 {
            return fail(format!(
                "metadata size {} != {}",
                metadata.size,
                payload.len()
            ));
        }
        let entries = fs
            .list_dir("conformance", 2)
            .await
            .map_err(|error| format!("list_dir failed: {error}"))?;
        if !entries.iter().any(|entry| entry.path.ends_with("file.bin")) {
            return fail("list_dir did not surface the written file");
        }
        fs.rename("conformance/dir/file.bin", "conformance/dir/renamed.bin")
            .await
            .map_err(|error| format!("rename failed: {error}"))?;
        if fs
            .exists("conformance/dir/file.bin")
            .await
            .map_err(|error| format!("exists failed: {error}"))?
        {
            return fail("source still exists after rename");
        }

        if ctx.caps().fs.permissions {
            fs.set_permissions("conformance/dir/renamed.bin", 0o600)
                .await
                .map_err(|error| format!("set_permissions failed: {error}"))?;
            let metadata = fs
                .metadata("conformance/dir/renamed.bin")
                .await
                .map_err(|error| format!("metadata failed: {error}"))?;
            if let Some(mode) = metadata.mode {
                if mode & 0o777 != 0o600 {
                    return fail(format!("mode {mode:o} after chmod 600"));
                }
            }
        }

        fs.delete("conformance", true)
            .await
            .map_err(|error| format!("recursive delete failed: {error}"))?;
        if fs
            .exists("conformance")
            .await
            .map_err(|error| format!("exists failed: {error}"))?
        {
            return fail("directory still exists after recursive delete");
        }
        // Delete is idempotent by contract: an already-deleted (or
        // never-existing) path succeeds.
        fs.delete("conformance", true)
            .await
            .map_err(|error| format!("repeated delete failed: {error}"))?;
        fs.delete("conformance-never-existed", false)
            .await
            .map_err(|error| format!("delete of a missing path failed: {error}"))?;
        PASS
    }
    .await;
    cleanup(&sandbox).await;
    outcome
}

/// Grep must return matches whether the target is a directory or a
/// single file — tools like ripgrep omit the file name for a lone file
/// operand, and a provider (or the derived implementation) must not let
/// that change the result shape.
async fn search_greps_directories_and_single_files(ctx: &Conformance) -> CheckOutcome {
    let sandbox = ctx.ready().await?;
    let outcome = async {
        sandbox
            .fs()
            .write(
                "conformance-grep/needle.txt",
                b"alpha needle beta\nplain line\n",
            )
            .await
            .map_err(|error| format!("write failed: {error}"))?;
        let derived;
        let search: &dyn Search = if let Some(native) = sandbox.search() {
            native
        } else {
            derived = DerivedSearch::new(sandbox.exec());
            &derived
        };
        for path in ["conformance-grep", "conformance-grep/needle.txt"] {
            let matches = search
                .grep("needle", path, &GrepOptions::default())
                .await
                .map_err(|error| format!("grep of {path} failed: {error}"))?;
            if matches.len() != 1 {
                return fail(format!(
                    "grep of {path} returned {} matches, expected 1",
                    matches.len()
                ));
            }
            if matches[0].line_number != 1 || !matches[0].line.contains("needle") {
                return fail(format!("grep of {path} returned {:?}", matches[0]));
            }
        }
        PASS
    }
    .await;
    cleanup(&sandbox).await;
    outcome
}

async fn unsupported_actions_say_so(ctx: &Conformance) -> CheckOutcome {
    let sandbox = ctx.create().await?;
    // The per-sandbox set is authoritative: a provider may narrow its
    // upper bound by sandbox class (Daytona masks VM-only verbs on
    // container sandboxes), and honesty is judged against the handle.
    let caps = sandbox.capabilities().clone();
    let outcome = async {
        let mut wrong: Vec<String> = Vec::new();
        let mut check = |name: &str, declared: bool, result: Result<(), Error>| match result {
            Err(Error::Unsupported { .. }) if declared => {
                wrong.push(format!("{name}: declared but returned Unsupported"));
            }
            Err(Error::Unsupported { .. }) => {}
            _ if declared => {}
            Ok(()) => wrong.push(format!("{name}: undeclared but succeeded")),
            // A non-Unsupported error for an undeclared capability is
            // wrong too, but tolerated: some providers reject earlier.
            Err(_) => {}
        };
        check("pause", caps.lifecycle.pause, sandbox.pause().await);
        check("archive", caps.lifecycle.archive, sandbox.archive().await);
        check("recover", caps.lifecycle.recover, sandbox.recover().await);
        check(
            "refresh_activity",
            caps.lifecycle.refresh_activity,
            sandbox.refresh_activity().await,
        );
        check(
            "resize",
            caps.lifecycle.resize,
            sandbox
                .resize(&{
                    let mut resources = Resources::default();
                    resources.cpu_cores = Some(1);
                    resources
                })
                .await,
        );
        check(
            "set_timers",
            caps.lifecycle.timers,
            sandbox
                .set_timers(&sandbox_driver::LifecycleTimers::default())
                .await,
        );
        check(
            "set_labels",
            caps.lifecycle.labels,
            sandbox.set_labels(&BTreeMap::new()).await,
        );
        check(
            "update_network",
            caps.lifecycle.update_network,
            sandbox.update_network(&NetworkPolicy::AllowAll).await,
        );
        check(
            "undelete",
            caps.lifecycle.undelete,
            ctx.provider.undelete(sandbox.id(), None).await.map(|_| ()),
        );
        // Handle-producing verbs are exercised only in the undeclared
        // direction: expect a clean Unsupported, never a real resource.
        if !caps.lifecycle.fork {
            match sandbox.fork(&sandbox_driver::ForkOptions::default()).await {
                Err(Error::Unsupported { .. }) => {}
                Err(error) => wrong.push(format!("fork: expected Unsupported, got {error}")),
                Ok(forked) => {
                    let _ = forked.delete().await;
                    wrong.push("fork: undeclared but succeeded".to_owned());
                }
            }
        }
        if !caps.lifecycle.snapshot_sandbox {
            match sandbox
                .snapshot(&sandbox_driver::SandboxSnapshotOptions::default())
                .await
            {
                Err(Error::Unsupported { .. }) => {}
                Err(error) => {
                    wrong.push(format!("snapshot: expected Unsupported, got {error}"));
                }
                Ok(_) => wrong.push("snapshot: undeclared but succeeded".to_owned()),
            }
        }
        if wrong.is_empty() {
            PASS
        } else {
            fail(wrong.join("; "))
        }
    }
    .await;
    cleanup(&sandbox).await;
    outcome
}

async fn pause_resume_cycle(ctx: &Conformance) -> CheckOutcome {
    if !ctx.caps().lifecycle.pause {
        return Ok(Some("capability lifecycle.pause not declared".to_owned()));
    }
    let sandbox = ctx.ready().await?;
    // The provider's upper bound may be narrowed per sandbox class.
    if !sandbox.capabilities().lifecycle.pause {
        cleanup(&sandbox).await;
        return Ok(Some(
            "lifecycle.pause masked for this sandbox's class".to_owned(),
        ));
    }
    let outcome = async {
        sandbox
            .pause()
            .await
            .map_err(|error| format!("pause failed: {error}"))?;
        wait_for_state(sandbox.as_ref(), SandboxState::Paused, &ctx.wait)
            .await
            .map_err(|error| format!("never reached Paused: {error}"))?;
        sandbox
            .resume()
            .await
            .map_err(|error| format!("resume failed: {error}"))?;
        wait_for_state(sandbox.as_ref(), SandboxState::Running, &ctx.wait)
            .await
            .map_err(|error| format!("never returned to Running: {error}"))?;
        // The sandbox must still work after the cycle.
        let result = sandbox
            .exec()
            .run(&ExecSpec::new("echo alive").timeout(Duration::from_secs(30)))
            .await
            .map_err(|error| format!("exec after resume failed: {error}"))?;
        if !result.success() {
            return fail("exec after resume did not succeed");
        }
        PASS
    }
    .await;
    cleanup(&sandbox).await;
    outcome
}

async fn fork_preserves_live_process_state(ctx: &Conformance) -> CheckOutcome {
    if !ctx.caps().lifecycle.fork {
        return Ok(Some("capability lifecycle.fork not declared".to_owned()));
    }
    let sandbox = ctx.ready().await?;
    if !sandbox.capabilities().lifecycle.fork {
        cleanup(&sandbox).await;
        return Ok(Some(
            "lifecycle.fork masked for this sandbox's class".to_owned(),
        ));
    }

    let prepare = sandbox
        .exec()
        .run(
            &ExecSpec::new(
                "printf preserved > /tmp/sandbox-driver-fork-marker; \
                 nohup sh -c 'echo $$ > /tmp/sandbox-driver-fork-pid; \
                 while :; do sleep 1; done' </dev/null >/dev/null 2>&1 & \
                 for i in 1 2 3 4 5; do test -s /tmp/sandbox-driver-fork-pid && break; sleep 1; done; \
                 cat /tmp/sandbox-driver-fork-pid",
            )
            .timeout(Duration::from_secs(30)),
        )
        .await;
    let source_pid = match prepare {
        Ok(result) if result.success() => result.stdout_lossy().trim().to_owned(),
        Ok(result) => {
            cleanup(&sandbox).await;
            return fail(format!(
                "fork process setup failed: {}",
                result.stderr_lossy()
            ));
        }
        Err(error) => {
            cleanup(&sandbox).await;
            return fail(format!("fork process setup failed: {error}"));
        }
    };

    let forked = match sandbox.fork(&sandbox_driver::ForkOptions::default()).await {
        Ok(forked) => forked,
        Err(error) => {
            cleanup(&sandbox).await;
            return fail(format!("fork failed: {error}"));
        }
    };
    let outcome = async {
        let status = forked
            .describe()
            .await
            .map_err(|error| format!("describing fork failed: {error}"))?;
        if status.state != SandboxState::Running {
            return fail(format!("fork returned in state {:?}", status.state));
        }
        let result = forked
            .exec()
            .run(
                &ExecSpec::new(
                    "pid=$(cat /tmp/sandbox-driver-fork-pid); \
                     kill -0 \"$pid\"; printf '%s ' \"$pid\"; \
                     cat /tmp/sandbox-driver-fork-marker",
                )
                .timeout(Duration::from_secs(30)),
            )
            .await
            .map_err(|error| format!("checking forked process failed: {error}"))?;
        if !result.success() {
            return fail(format!(
                "forked process is not running: {}",
                result.stderr_lossy()
            ));
        }
        let expected = format!("{source_pid} preserved");
        if result.stdout_lossy().trim() != expected {
            return fail(format!(
                "fork did not preserve PID and filesystem: got {:?}, expected {expected:?}",
                result.stdout_lossy().trim()
            ));
        }
        PASS
    }
    .await;
    cleanup(&forked).await;
    cleanup(&sandbox).await;
    outcome
}

async fn snapshot_modes_are_honest(ctx: &Conformance) -> CheckOutcome {
    if !ctx.caps().lifecycle.snapshot_sandbox {
        return Ok(Some(
            "capability lifecycle.snapshot_sandbox not declared".to_owned(),
        ));
    }
    let sandbox = ctx.ready().await?;
    let snapshot_caps = sandbox.capabilities().snapshots.clone().unwrap_or_default();
    let modes = [
        (
            SnapshotMode::Filesystem,
            snapshot_caps.filesystem_from_sandbox,
            Capability::SnapshotsFilesystem,
        ),
        (
            SnapshotMode::LiveProcessState,
            snapshot_caps.live_process_state_from_sandbox,
            Capability::SnapshotsLiveProcessState,
        ),
    ];
    let mut checked = false;
    let mut failure = None;
    for (mode, declared, capability) in modes {
        if declared {
            continue;
        }
        checked = true;
        let mut options = sandbox_driver::SandboxSnapshotOptions::default();
        options.mode = mode;
        match sandbox.snapshot(&options).await {
            Err(Error::Unsupported { capability: actual }) if actual == capability => {}
            Err(error) => {
                failure = Some(format!(
                    "{mode:?}: expected Unsupported({capability}), got {error}"
                ));
                break;
            }
            Ok(id) => {
                failure = Some(format!(
                    "undeclared snapshot mode {mode:?} created snapshot {id}"
                ));
                break;
            }
        }
    }
    cleanup(&sandbox).await;
    if let Some(failure) = failure {
        fail(failure)
    } else if checked {
        PASS
    } else {
        Ok(Some("all sandbox snapshot modes are declared".to_owned()))
    }
}

async fn stdio_process_round_trips(ctx: &Conformance) -> CheckOutcome {
    if !ctx.caps().exec.stdio_process {
        // The default must be a clean Unsupported.
        let sandbox = ctx.create().await?;
        let outcome = match sandbox.exec().spawn_stdio(&SpawnSpec::new("cat")).await {
            Err(Error::Unsupported { .. }) => Ok(Some(
                "capability exec.stdio_process not declared".to_owned(),
            )),
            Err(other) => fail(format!("expected Unsupported, got {other}")),
            Ok(_) => fail("stdio_process undeclared but spawn succeeded"),
        };
        cleanup(&sandbox).await;
        return outcome;
    }
    let sandbox = ctx.ready().await?;
    if !sandbox.capabilities().exec.stdio_process {
        cleanup(&sandbox).await;
        return Ok(Some(
            "exec.stdio_process masked for this sandbox".to_owned(),
        ));
    }
    let outcome = async {
        let mut process = sandbox
            .exec()
            .spawn_stdio(&SpawnSpec::new("cat"))
            .await
            .map_err(|error| format!("spawn failed: {error}"))?;
        process
            .stdin
            .write_all(b"ping\n")
            .await
            .map_err(|error| format!("write failed: {error}"))?;
        process
            .stdin
            .flush()
            .await
            .map_err(|error| format!("flush failed: {error}"))?;
        let mut buffer = [0u8; 5];
        process
            .stdout
            .read_exact(&mut buffer)
            .await
            .map_err(|error| format!("read failed: {error}"))?;
        if &buffer != b"ping\n" {
            return fail(format!("round trip mismatch: {buffer:?}"));
        }
        process.handle.terminate().await;
        let _ = process.handle.wait().await;
        PASS
    }
    .await;
    cleanup(&sandbox).await;
    outcome
}

async fn pty_is_bidirectional(ctx: &Conformance) -> CheckOutcome {
    if ctx.caps().pty.is_none() {
        return Ok(Some("pty not declared".to_owned()));
    }
    let sandbox = ctx.ready().await?;
    let outcome = async {
        let Some(pty) = sandbox.pty() else {
            return fail("pty declared but facet is absent");
        };
        let session = pty
            .open(&PtyOptions::default())
            .await
            .map_err(|error| format!("open failed: {error}"))?;
        let marker = format!("pty-conformance-{}", process::id());
        let exchange = async {
            let input = async {
                if sandbox
                    .capabilities()
                    .pty
                    .as_ref()
                    .is_some_and(|caps| caps.resize)
                {
                    session
                        .resize(PtySize {
                            rows: 40,
                            cols: 100,
                        })
                        .await
                        .map_err(|error| format!("resize failed: {error}"))?;
                }
                session
                    .write_input(format!("printf '{marker}\\n'; exit\n").as_bytes())
                    .await
                    .map_err(|error| format!("input failed: {error}"))
            };
            let output = async {
                let mut output = Vec::new();
                while let Some(chunk) = session
                    .read_output()
                    .await
                    .map_err(|error| format!("output failed: {error}"))?
                {
                    output.extend(chunk);
                    if String::from_utf8_lossy(&output).contains(&marker) {
                        return Ok::<_, String>(());
                    }
                }
                Err("PTY ended before the marker appeared".to_owned())
            };
            let (input, output) = tokio::join!(input, output);
            input?;
            output
        };
        time::timeout(Duration::from_secs(30), exchange)
            .await
            .map_err(|_| "PTY exchange timed out".to_owned())??;
        session
            .close()
            .await
            .map_err(|error| format!("close failed: {error}"))?;
        PASS
    }
    .await;
    cleanup(&sandbox).await;
    outcome
}

async fn logs_follow_streams_and_cancels(ctx: &Conformance) -> CheckOutcome {
    if ctx.caps().logs.is_none() {
        return Ok(Some("logs not declared".to_owned()));
    }
    let Some(spec) = ctx.specs.entrypoint_logs_spec() else {
        return fail("logs declared but no entrypoint-log spec was configured");
    };
    let sandbox = ctx
        .provider
        .create(&spec, None)
        .await
        .map_err(|error| format!("create log-producing sandbox failed: {error}"))?;
    if sandbox.capabilities().logs.is_none() {
        cleanup(&sandbox).await;
        return Ok(Some("logs not declared for this sandbox".to_owned()));
    }
    let outcome = async {
        let Some(logs) = sandbox.logs() else {
            return fail("logs declared but facet is absent");
        };

        // A follow stream is long-lived. Timing it out drops the future,
        // which must cancel the provider-side stream without wedging the
        // sandbox or a plugin connection.
        let discard: LogSink = Arc::new(|_| Box::pin(async { Ok(()) }));
        match time::timeout(
            Duration::from_secs(5),
            logs.follow(LogSource::Entrypoint, discard),
        )
        .await
        {
            Err(_) => {}
            Ok(Ok(())) => return fail("log follow ended before it could be cancelled"),
            Ok(Err(error)) => {
                return fail(format!("log follow failed before cancellation: {error}"));
            }
        }

        time::timeout(Duration::from_secs(30), sandbox.describe())
            .await
            .map_err(|_| "describe timed out after cancelling log follow".to_owned())?
            .map_err(|error| format!("describe failed after cancelling log follow: {error}"))?;

        // A sink error must stop the stream and reach the caller unchanged.
        // Saving the chunk first also proves that bytes reached the sink.
        let output = Arc::new(Mutex::new(Vec::new()));
        let sink_output = Arc::clone(&output);
        let rejecting_sink: LogSink = Arc::new(move |chunk| {
            sink_output.lock().expect("log output lock").extend(chunk);
            Box::pin(async { Err(Error::invalid_spec("log_sink", "conformance sentinel")) })
        });
        match time::timeout(
            Duration::from_secs(30),
            logs.follow(LogSource::Entrypoint, rejecting_sink),
        )
        .await
        {
            Ok(Err(Error::InvalidSpec { field, reason }))
                if field == "log_sink" && reason == "conformance sentinel" => {}
            Ok(Err(error)) => return fail(format!("log sink error changed: {error}")),
            Ok(Ok(())) => return fail("log follow ignored the sink error"),
            Err(_) => return fail("entrypoint logs produced no output within 30 seconds"),
        }
        if output.lock().expect("log output lock").is_empty() {
            return fail("entrypoint log sink received an empty chunk");
        }
        PASS
    }
    .await;
    cleanup(&sandbox).await;
    outcome
}

async fn attach_and_list_by_label(ctx: &Conformance) -> CheckOutcome {
    let marker = format!("conformance-{}", process::id());
    let mut spec = ctx.specs.spec();
    spec.labels
        .insert("sandbox-driver-conformance".to_owned(), marker.clone());
    let sandbox = ctx
        .provider
        .create(&spec, None)
        .await
        .map_err(|error| format!("create failed: {error}"))?;
    let outcome = async {
        let attached = ctx
            .provider
            .attach(sandbox.id(), None)
            .await
            .map_err(|error| format!("attach failed: {error}"))?;
        if attached.id() != sandbox.id() {
            return fail("attach returned a different sandbox");
        }
        let mut filter = SandboxFilter::default();
        filter
            .labels
            .insert("sandbox-driver-conformance".to_owned(), marker.clone());
        let listed = ctx
            .provider
            .list(&filter)
            .await
            .map_err(|error| format!("list failed: {error}"))?;
        if listed.len() != 1 || listed[0].id != *sandbox.id() {
            return fail(format!("label filter returned {} sandboxes", listed.len()));
        }
        PASS
    }
    .await;
    cleanup(&sandbox).await;
    outcome
}

async fn services_match_capabilities(ctx: &Conformance) -> CheckOutcome {
    let caps = ctx.caps();
    let mut wrong: Vec<String> = Vec::new();
    if caps.snapshots.is_some() != ctx.provider.snapshots().is_some() {
        wrong.push(format!(
            "snapshots service presence ({}) disagrees with capabilities ({})",
            ctx.provider.snapshots().is_some(),
            caps.snapshots.is_some()
        ));
    }
    if caps.volumes.is_some() != ctx.provider.volumes().is_some() {
        wrong.push(format!(
            "volumes service presence ({}) disagrees with capabilities ({})",
            ctx.provider.volumes().is_some(),
            caps.volumes.is_some()
        ));
    }
    let sandbox = ctx.create().await?;
    let sandbox_caps = sandbox.capabilities();
    if sandbox_caps.access.preview_urls != sandbox.preview_urls().is_some() {
        wrong.push("preview_urls facet presence disagrees with capabilities".to_owned());
    }
    if sandbox_caps.access.ssh != sandbox.ssh().is_some() {
        wrong.push("ssh facet presence disagrees with capabilities".to_owned());
    }
    if sandbox_caps.access.shell_command != sandbox.shell_command().is_some() {
        wrong.push("shell_command facet presence disagrees with capabilities".to_owned());
    }
    if sandbox_caps.pty.is_some() != sandbox.pty().is_some() {
        wrong.push("pty facet presence disagrees with capabilities".to_owned());
    }
    if sandbox_caps.logs.is_some() != sandbox.logs().is_some() {
        wrong.push("logs facet presence disagrees with capabilities".to_owned());
    }
    if sandbox_caps.access.web_terminal != sandbox.web_terminal().is_some() {
        wrong.push("web_terminal facet presence disagrees with capabilities".to_owned());
    }
    if sandbox_caps.access.vnc != sandbox.vnc().is_some() {
        wrong.push("vnc facet presence disagrees with capabilities".to_owned());
    }
    cleanup(&sandbox).await;
    if wrong.is_empty() {
        PASS
    } else {
        fail(wrong.join("; "))
    }
}

async fn ssh_access_matches_capabilities(ctx: &Conformance) -> CheckOutcome {
    if !ctx.caps().access.ssh {
        return Ok(Some("capability access.ssh not declared".to_owned()));
    }
    let sandbox = ctx.ready().await?;
    let caps = sandbox.capabilities().access.clone();
    let Some(ssh) = sandbox.ssh() else {
        cleanup(&sandbox).await;
        return fail("access.ssh is declared but the SSH facet is absent");
    };

    let outcome = async {
        let access = if caps.ssh_ttl {
            ssh.ssh_access(Some(Duration::from_secs(120)))
                .await
                .map_err(|error| format!("TTL SSH access failed: {error}"))?
        } else {
            match ssh.ssh_access(Some(Duration::from_secs(120))).await {
                Err(Error::Unsupported {
                    capability: Capability::SshTtl,
                }) => {}
                Err(error) => {
                    return fail(format!(
                        "undeclared SSH TTL: expected Unsupported(access.ssh.ttl), got {error}"
                    ));
                }
                Ok(_) => return fail("undeclared SSH TTL was accepted"),
            }
            ssh.ssh_access(None)
                .await
                .map_err(|error| format!("SSH access without TTL failed: {error}"))?
        };

        if access.command.trim().is_empty() {
            return fail("SSH access returned an empty command");
        }
        if caps.ssh_revoke {
            let Some(token) = access.token.as_deref() else {
                return fail("access.ssh.revoke is declared but SSH access returned no token");
            };
            ssh.revoke_ssh_access(token)
                .await
                .map_err(|error| format!("SSH revoke failed: {error}"))?;
            PASS
        } else {
            match ssh.revoke_ssh_access("sandbox-driver-conformance").await {
                Err(Error::Unsupported {
                    capability: Capability::SshRevoke,
                }) => PASS,
                Err(error) => fail(format!(
                    "undeclared SSH revoke: expected Unsupported(access.ssh.revoke), got {error}"
                )),
                Ok(()) => fail("undeclared SSH revoke succeeded"),
            }
        }
    }
    .await;
    cleanup(&sandbox).await;
    outcome
}

async fn shell_command_access_matches_capabilities(ctx: &Conformance) -> CheckOutcome {
    if !ctx.caps().access.shell_command {
        return Ok(Some(
            "capability access.shell_command not declared".to_owned(),
        ));
    }
    let sandbox = ctx.ready().await?;
    let outcome = async {
        let Some(access) = sandbox.shell_command() else {
            return fail("access.shell_command is declared but the ShellCommand facet is absent");
        };
        let command = access
            .shell_command()
            .await
            .map_err(|error| format!("shell command access failed: {error}"))?;
        if command.trim().is_empty() {
            return fail("ShellCommand returned an empty command");
        }
        PASS
    }
    .await;
    cleanup(&sandbox).await;
    outcome
}

async fn volume_round_trip(ctx: &Conformance) -> CheckOutcome {
    let Some(volumes) = ctx.provider.volumes() else {
        return Ok(Some("volumes service not declared".to_owned()));
    };
    let name = format!("conformance-{}-{}", process::id(), {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.subsec_nanos())
    });
    let id = match volumes
        .create(&sandbox_driver::VolumeSpec::new(name.clone()), None)
        .await
    {
        Ok(id) => id,
        // Capabilities describe the backend, not the credential; a
        // permission-scoped key skips rather than fails this check.
        Err(Error::Provider(provider))
            if provider.code.as_deref() == Some("403")
                || provider.code.as_deref() == Some("401") =>
        {
            return Ok(Some("credential lacks volume permissions".to_owned()));
        }
        Err(Error::Auth(_)) => {
            return Ok(Some("credential lacks volume permissions".to_owned()));
        }
        Err(error) => return fail(format!("volume create failed: {error}")),
    };

    // Poll briefly for a settled state; elastic backends are quick.
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        let status = volumes
            .get(&id)
            .await
            .map_err(|error| format!("volume get failed: {error}"))?;
        match status.state {
            sandbox_driver::VolumeState::Ready => break,
            sandbox_driver::VolumeState::Error => {
                let _ = volumes.delete(&id, None).await;
                return fail(format!(
                    "volume entered error state: {:?}",
                    status.error_reason
                ));
            }
            _ if Instant::now() >= deadline => {
                let _ = volumes.delete(&id, None).await;
                return fail("volume never became ready".to_owned());
            }
            _ => time::sleep(Duration::from_secs(2)).await,
        }
    }

    let listed = volumes
        .list()
        .await
        .map_err(|error| format!("volume list failed: {error}"))?;
    if !listed.iter().any(|status| status.id == id) {
        let _ = volumes.delete(&id, None).await;
        return fail("created volume missing from list".to_owned());
    }
    volumes
        .delete(&id, None)
        .await
        .map_err(|error| format!("volume delete failed: {error}"))?;
    volumes
        .delete(&id, None)
        .await
        .map_err(|error| format!("second volume delete failed: {error}"))?;
    PASS
}

/// A spec field the capability set disclaims must be rejected with the
/// matching `Unsupported`, never silently dropped.
async fn exec_rejects_undeclared_stdin_and_cancel(ctx: &Conformance) -> CheckOutcome {
    let caps = ctx.caps();
    if caps.exec.stdin && caps.exec.cancel {
        return Ok(Some(
            "exec.stdin and exec.cancel are both declared".to_owned(),
        ));
    }
    let sandbox = ctx.ready().await?;
    let outcome = async {
        if !caps.exec.stdin {
            let spec = ExecSpec::new("cat")
                .stdin(b"dropped?".to_vec())
                .timeout(Duration::from_secs(30));
            match sandbox
                .exec()
                .run_streaming(&spec, ExecControls::default())
                .await
            {
                Err(Error::Unsupported {
                    capability: Capability::ExecStdin,
                }) => {}
                Err(other) => {
                    return fail(format!("stdin: expected Unsupported(exec.stdin): {other}"));
                }
                Ok(_) => return fail("undeclared stdin was accepted (or dropped)"),
            }
        }
        if !caps.exec.cancel {
            let controls = ExecControls {
                cancel: Some(CancellationToken::new()),
                ..ExecControls::default()
            };
            let spec = ExecSpec::new("true").timeout(Duration::from_secs(30));
            match sandbox.exec().run_streaming(&spec, controls).await {
                Err(Error::Unsupported {
                    capability: Capability::ExecCancel,
                }) => {}
                Err(other) => {
                    return fail(format!(
                        "cancel: expected Unsupported(exec.cancel): {other}"
                    ));
                }
                Ok(_) => return fail("undeclared cancel token was accepted (or ignored)"),
            }
        }
        PASS
    }
    .await;
    cleanup(&sandbox).await;
    outcome
}

async fn fs_range_and_append_round_trip(ctx: &Conformance) -> CheckOutcome {
    let sandbox = ctx.ready().await?;
    let outcome = async {
        let fs = sandbox.fs();
        fs.write("conformance-range/base.bin", b"0123456789")
            .await
            .map_err(|error| format!("write failed: {error}"))?;
        let middle = fs
            .read_range("conformance-range/base.bin", 2, Some(5))
            .await
            .map_err(|error| format!("read_range failed: {error}"))?;
        if middle != b"23456" {
            return fail(format!("read_range(2,5) returned {middle:?}"));
        }
        let tail = fs
            .read_range("conformance-range/base.bin", 7, None)
            .await
            .map_err(|error| format!("read_range to EOF failed: {error}"))?;
        if tail != b"789" {
            return fail(format!("read_range(7,None) returned {tail:?}"));
        }
        let past = fs
            .read_range("conformance-range/base.bin", 32, Some(4))
            .await
            .map_err(|error| format!("read_range past EOF failed: {error}"))?;
        if !past.is_empty() {
            return fail(format!("read past EOF returned {past:?}"));
        }

        // Append creates the file (and parents) and extends it.
        fs.write_append("conformance-range/appended.bin", b"first-")
            .await
            .map_err(|error| format!("first append failed: {error}"))?;
        fs.write_append("conformance-range/appended.bin", b"second")
            .await
            .map_err(|error| format!("second append failed: {error}"))?;
        let combined = fs
            .read("conformance-range/appended.bin")
            .await
            .map_err(|error| format!("read after append failed: {error}"))?;
        if combined != b"first-second" {
            return fail(format!(
                "append round trip returned {:?}",
                String::from_utf8_lossy(&combined)
            ));
        }
        fs.delete("conformance-range", true)
            .await
            .map_err(|error| format!("cleanup delete failed: {error}"))?;
        PASS
    }
    .await;
    cleanup(&sandbox).await;
    outcome
}

/// Background services: spawn outlives its exec, reports status, serves
/// logs, and stops idempotently — via the native facet when declared,
/// otherwise the library's derived implementation.
async fn background_services_round_trip(ctx: &Conformance) -> CheckOutcome {
    let sandbox = ctx.ready().await?;
    let outcome = async {
        if sandbox.capabilities().services.native != sandbox.services().is_some() {
            return fail("services facet presence disagrees with services.native");
        }
        let derived;
        let services: &dyn Services = if let Some(native) = sandbox.services() {
            native
        } else {
            derived = DerivedServices::new(sandbox.exec());
            &derived
        };

        let spec = ServiceSpec::new("while true; do echo tick; sleep 0.2; done");
        let id = services
            .spawn(&spec)
            .await
            .map_err(|error| format!("spawn failed: {error}"))?;
        // The service must be observable as running and produce logs.
        let mut running = false;
        for _ in 0..20 {
            let status = services
                .status(&id)
                .await
                .map_err(|error| format!("status failed: {error}"))?;
            if status.running {
                running = true;
                break;
            }
            time::sleep(Duration::from_millis(250)).await;
        }
        if !running {
            return fail("service never reported running");
        }
        let mut saw_logs = false;
        for _ in 0..20 {
            let logs = services
                .logs(&id, 4096)
                .await
                .map_err(|error| format!("logs failed: {error}"))?;
            if String::from_utf8_lossy(&logs).contains("tick") {
                saw_logs = true;
                break;
            }
            time::sleep(Duration::from_millis(250)).await;
        }
        if !saw_logs {
            return fail("service logs never surfaced output");
        }

        services
            .stop(&id)
            .await
            .map_err(|error| format!("stop failed: {error}"))?;
        let mut stopped = false;
        for _ in 0..20 {
            let status = services
                .status(&id)
                .await
                .map_err(|error| format!("status after stop failed: {error}"))?;
            if !status.running {
                stopped = true;
                break;
            }
            time::sleep(Duration::from_millis(250)).await;
        }
        if !stopped {
            return fail("service still running after stop");
        }
        // Stop is idempotent, and an unknown id reports not running.
        services
            .stop(&id)
            .await
            .map_err(|error| format!("second stop failed: {error}"))?;
        let unknown = sandbox_driver::ServiceId::try_new("conformance-unknown-service")
            .map_err(|error| error.to_string())?;
        let status = services
            .status(&unknown)
            .await
            .map_err(|error| format!("status of unknown id failed: {error}"))?;
        if status.running {
            return fail("unknown service id reported running");
        }
        PASS
    }
    .await;
    cleanup(&sandbox).await;
    outcome
}

/// `health` must answer — a working provider (this suite just created
/// sandboxes on it) must not report itself unreachable or unauthorized.
async fn provider_health_answers(ctx: &Conformance) -> CheckOutcome {
    let health = ctx
        .provider
        .health()
        .await
        .map_err(|error| format!("health failed: {error}"))?;
    match health.status {
        HealthStatus::Ok | HealthStatus::Unknown => PASS,
        status => fail(format!(
            "a working provider reported {status:?}: {:?} (missing: {:?})",
            health.message, health.missing_permissions
        )),
    }
}

async fn create_emits_terminal_events(ctx: &Conformance) -> CheckOutcome {
    let observer = Arc::new(RecordingEventObserver::default());
    let context = EventContext::new(observer.clone());
    let sandbox = ctx
        .provider
        .create(&ctx.specs.spec(), Some(context))
        .await
        .map_err(|error| format!("create failed: {error}"))?;
    // The terminal event must already be visible when create returns.
    let seen = observer.events.lock().expect("events lock").clone();
    sandbox
        .delete()
        .await
        .map_err(|error| format!("delete failed: {error}"))?;
    // Delete has the same terminal-before-return contract.
    let all_seen = observer.events.lock().expect("events lock").clone();

    let Some(first) = seen.first() else {
        return fail("create emitted no events");
    };
    if !matches!(first.body, EventBody::OperationStarted {
        action: Action::Create,
    }) {
        return fail(format!("first create event was {:?}", first.body));
    }
    let Some(last) = seen.last() else {
        unreachable!("the first event exists");
    };
    if !matches!(last.body, EventBody::OperationCompleted {
        action: Action::Create,
        ..
    }) {
        return fail(format!(
            "last create event was not completed: {:?}",
            last.body
        ));
    }
    if first.operation_id.is_none() || first.operation_id != last.operation_id {
        return fail("create start and completion have different operation ids");
    }
    if !matches!(
        &last.subject,
        sandbox_driver::EventSubject::Sandbox { id: Some(id), .. } if id == sandbox.id()
    ) {
        return fail("create completion does not identify the created sandbox");
    }
    if seen.windows(2).any(|pair| {
        pair[0].source_id() != pair[1].source_id()
            || pair[0].sequence().checked_add(1) != Some(pair[1].sequence())
    }) {
        return fail("create event source or sequence is not continuous");
    }
    let delete_events: Vec<&Event> = all_seen
        .iter()
        .filter(|event| {
            matches!(
                event.body,
                EventBody::OperationStarted {
                    action: Action::Delete,
                } | EventBody::OperationProgress {
                    action: Action::Delete,
                    ..
                } | EventBody::OperationCompleted {
                    action: Action::Delete,
                    ..
                } | EventBody::OperationFailed {
                    action: Action::Delete,
                    ..
                }
            )
        })
        .collect();
    let (Some(delete_started), Some(delete_terminal)) =
        (delete_events.first(), delete_events.last())
    else {
        return fail(format!(
            "delete emitted {} lifecycle events",
            delete_events.len()
        ));
    };
    if !matches!(delete_started.body, EventBody::OperationStarted {
        action: Action::Delete,
    }) || !matches!(delete_terminal.body, EventBody::OperationCompleted {
        action: Action::Delete,
        ..
    }) || delete_started.operation_id != delete_terminal.operation_id
        || delete_events
            .iter()
            .any(|event| event.operation_id != delete_started.operation_id)
        || delete_events
            .iter()
            .filter(|event| matches!(event.body, EventBody::OperationStarted { .. }))
            .count()
            != 1
        || delete_events
            .iter()
            .filter(|event| event.body.is_terminal())
            .count()
            != 1
    {
        return fail("delete start and completion are not a paired operation");
    }
    if all_seen.windows(2).any(|pair| {
        pair[0].source_id() != pair[1].source_id()
            || pair[0].sequence().checked_add(1) != Some(pair[1].sequence())
    }) {
        return fail("event source or sequence changed across create and delete");
    }
    PASS
}
