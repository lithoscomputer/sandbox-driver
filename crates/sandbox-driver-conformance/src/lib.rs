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
//! safe to run against real (billed) providers — expect roughly a dozen
//! short-lived sandboxes per run.

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use std::{fmt, process};

use sandbox_driver::{
    Capability, DerivedSearch, Error, ExecControls, ExecSpec, GrepOptions, OutputStream, Sandbox,
    SandboxEvent, SandboxFilter, SandboxId, SandboxProvider, SandboxSpec, SandboxState, Search,
    SpawnSpec, Termination, WaitOptions, activate, wait_for_state,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time;
use tokio_util::sync::CancellationToken;

type SeenChunks = Arc<Mutex<Vec<(OutputStream, Vec<u8>)>>>;

/// Produces a provider-appropriate creation spec for each check.
pub struct SpecFactory {
    make: Box<dyn Fn() -> SandboxSpec + Send + Sync>,
}

impl SpecFactory {
    pub fn new(make: impl Fn() -> SandboxSpec + Send + Sync + 'static) -> Self {
        Self {
            make: Box::new(make),
        }
    }

    fn spec(&self) -> SandboxSpec {
        (self.make)()
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
            ("exec_reports_exit_codes", |ctx| {
                Box::pin(exec_reports_exit_codes(ctx))
            }),
            ("exec_env_vars_apply", |ctx| {
                Box::pin(exec_env_vars_apply(ctx))
            }),
            ("exec_output_is_binary_safe", |ctx| {
                Box::pin(exec_output_is_binary_safe(ctx))
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
            ("stdio_process_round_trips", |ctx| {
                Box::pin(stdio_process_round_trips(ctx))
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
        let sandbox = self.create().await?;
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
    PASS
}

async fn create_describe_delete(ctx: &Conformance) -> CheckOutcome {
    let sandbox = ctx.create().await?;
    let outcome = async {
        let status = sandbox
            .describe()
            .await
            .map_err(|error| format!("describe failed: {error}"))?;
        if status.id != *sandbox.id() {
            return fail("describe returned a different sandbox id");
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
    let sandbox = ctx.ready().await?;
    let outcome = async {
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
    let caps = ctx.caps().clone();
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
        if !caps.lifecycle.checkpoint {
            if let Err(error) = sandbox
                .checkpoint(&sandbox_driver::CheckpointOptions::default())
                .await
            {
                if !matches!(error, Error::Unsupported {
                    capability: Capability::LifecycleCheckpoint,
                }) {
                    wrong.push(format!("checkpoint: expected Unsupported, got {error}"));
                }
            } else {
                wrong.push("checkpoint: undeclared but succeeded".to_owned());
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
    if caps.access.preview_urls != sandbox.preview_urls().is_some() {
        wrong.push("preview_urls facet presence disagrees with capabilities".to_owned());
    }
    if caps.access.ssh != sandbox.ssh().is_some() {
        wrong.push("ssh facet presence disagrees with capabilities".to_owned());
    }
    cleanup(&sandbox).await;
    if wrong.is_empty() {
        PASS
    } else {
        fail(wrong.join("; "))
    }
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
        .create(&sandbox_driver::VolumeSpec::new(name.clone()))
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
                let _ = volumes.delete(&id).await;
                return fail(format!(
                    "volume entered error state: {:?}",
                    status.error_reason
                ));
            }
            _ if Instant::now() >= deadline => {
                let _ = volumes.delete(&id).await;
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
        let _ = volumes.delete(&id).await;
        return fail("created volume missing from list".to_owned());
    }
    volumes
        .delete(&id)
        .await
        .map_err(|error| format!("volume delete failed: {error}"))?;
    volumes
        .delete(&id)
        .await
        .map_err(|error| format!("second volume delete failed: {error}"))?;
    PASS
}

async fn create_emits_terminal_events(ctx: &Conformance) -> CheckOutcome {
    let events: Arc<Mutex<Vec<SandboxEvent>>> = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&events);
    let callback: sandbox_driver::EventCallback = Arc::new(move |event| {
        sink.lock().expect("events lock").push(event);
    });
    let sandbox = ctx
        .provider
        .create(&ctx.specs.spec(), Some(callback))
        .await
        .map_err(|error| format!("create failed: {error}"))?;
    cleanup(&sandbox).await;
    // Give the async delivery path a moment.
    time::sleep(Duration::from_millis(200)).await;
    let seen = events.lock().expect("events lock").clone();
    if seen.iter().any(SandboxEvent::is_terminal) {
        PASS
    } else {
        fail(format!(
            "no terminal event observed across create+delete ({} events)",
            seen.len()
        ))
    }
}
