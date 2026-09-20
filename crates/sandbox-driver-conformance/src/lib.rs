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

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use sandbox_driver::{Sandbox, SandboxProvider, SandboxSpec, WaitOptions, activate};
use tokio::time;

use crate::check::CheckFn;

mod check;
mod exec;
mod exec_stop;
mod exec_streaming;
mod facets;
mod fs;
mod git;
mod honesty;
mod lifecycle;
mod volumes;

/// Produces a provider-appropriate creation spec for each check.
pub struct SpecFactory {
    make:                 Box<dyn Fn() -> SandboxSpec + Send + Sync>,
    make_entrypoint_logs: Option<Box<dyn Fn() -> SandboxSpec + Send + Sync>>,
    git_clone_url:        Option<String>,
    one_shot_image:       Option<String>,
}

impl SpecFactory {
    pub fn new(make: impl Fn() -> SandboxSpec + Send + Sync + 'static) -> Self {
        Self {
            make:                 Box::new(make),
            make_entrypoint_logs: None,
            git_clone_url:        None,
            one_shot_image:       None,
        }
    }

    /// A registry image with `sh`, `cat`, `printf`, and `sleep`, for the
    /// one-shot container check. Providers that declare
    /// [`sandbox_driver::OneShot`] must configure one.
    #[must_use]
    pub fn with_one_shot_image(mut self, reference: impl Into<String>) -> Self {
        self.one_shot_image = Some(reference.into());
        self
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

    /// Overrides the sandbox-local `file://` clone fixture.
    ///
    /// Use this for providers whose native Git API accepts remote repository
    /// URLs only. The repository needs no specific contents or default branch;
    /// the check normalizes the clone before testing worktree operations.
    #[must_use]
    pub fn with_git_clone_url(mut self, url: impl Into<String>) -> Self {
        self.git_clone_url = Some(url.into());
        self
    }

    pub(crate) fn spec(&self) -> SandboxSpec {
        (self.make)()
    }

    pub(crate) fn entrypoint_logs_spec(&self) -> Option<SandboxSpec> {
        self.make_entrypoint_logs.as_ref().map(|make| make())
    }

    pub(crate) fn git_clone_url(&self) -> Option<&str> {
        self.git_clone_url.as_deref()
    }

    pub(crate) fn one_shot_image(&self) -> Option<&str> {
        self.one_shot_image.as_deref()
    }
}

/// Suite configuration.
pub struct Conformance {
    pub(crate) provider: Arc<dyn SandboxProvider>,
    pub(crate) specs:    SpecFactory,
    /// Per-check wall-clock budget; a hung provider fails, not hangs.
    pub check_timeout:   Duration,
    /// Wait options for state transitions (slow cloud providers need a
    /// longer deadline).
    pub wait:            WaitOptions,
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
        self.run_matching(|_| true).await
    }

    /// Runs checks selected by name, for focused reruns against expensive
    /// providers. The report contains only checks accepted by `include`.
    pub async fn run_matching(&self, include: impl Fn(&str) -> bool) -> Report {
        let mut results = Vec::new();
        for (name, check) in CHECKS {
            if !include(name) {
                continue;
            }
            tracing::info!(check = name, "conformance check starting");
            let outcome = match time::timeout(self.check_timeout, check(self)).await {
                Ok(Ok(None)) => Outcome::Passed,
                Ok(Ok(Some(reason))) => Outcome::Skipped { reason },
                Ok(Err(reason)) => Outcome::Failed { reason },
                Err(_) => Outcome::Failed {
                    reason: format!("check exceeded the {:?} budget", self.check_timeout),
                },
            };
            tracing::info!(check = name, ?outcome, "conformance check complete");
            results.push(CheckResult { name, outcome });
        }
        Report { results }
    }

    pub(crate) async fn create(&self) -> Result<Arc<dyn Sandbox>, String> {
        self.provider
            .create(&self.specs.spec(), None)
            .await
            .map_err(|error| format!("create failed: {error}"))
    }

    pub(crate) async fn ready(&self) -> Result<Arc<dyn Sandbox>, String> {
        let spec = self.specs.spec();
        self.ready_from_spec(&spec).await
    }

    pub(crate) async fn ready_from_spec(
        &self,
        spec: &SandboxSpec,
    ) -> Result<Arc<dyn Sandbox>, String> {
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

    pub(crate) fn caps(&self) -> &sandbox_driver::Capabilities {
        self.provider.capabilities()
    }
}

/// Builds the check registry from bare identifiers, so a check's report
/// name is always the name of the function that runs it.
macro_rules! checks {
    ($($module:ident :: $check:ident),* $(,)?) => {
        &[$((stringify!($check), |ctx| Box::pin($module::$check(ctx)))),*]
    };
}

/// Every check, in report order. The order is the suite's history, not
/// its module layout, so a consumer's report reads as it always has.
const CHECKS: &[(&str, CheckFn)] = checks![
    lifecycle::provider_identity_and_list,
    lifecycle::create_describe_delete,
    lifecycle::delete_is_idempotent,
    lifecycle::provider_deletes_by_id,
    lifecycle::attach_unknown_id_is_not_found,
    lifecycle::activate_passes_bash_probe,
    lifecycle::working_directory_is_effective,
    lifecycle::runtime_directory_is_private,
    exec::relative_working_dir_resolves,
    exec::exec_reports_exit_codes,
    exec::exec_env_vars_apply,
    exec::bash_helper_ignores_a_caller_bash_env,
    exec::exec_argv_is_literal,
    exec::exec_output_is_binary_safe,
    exec::exec_output_sanitization_is_consistent,
    exec::exec_stdin_round_trips,
    exec_stop::exec_timeout_terminates,
    exec_stop::exec_term_terminates,
    exec_stop::exec_kill_terminates,
    exec_stop::exec_term_does_not_escalate,
    exec_stop::exec_stop_grace_escalates_a_timeout,
    exec_stop::exec_stop_grace_escalates_a_term,
    exec::exec_reports_a_foreign_signal,
    exec::exec_reports_environment,
    exec_streaming::exec_streams_stdin,
    exec_streaming::exec_streaming_is_honest,
    exec_streaming::exec_streams_large_output_in_order,
    exec_streaming::exec_output_keeps_a_partial_last_line,
    facets::preview_url_reaches_a_listening_port,
    exec_streaming::exec_retention_accounting_is_consistent,
    exec_streaming::concurrent_streams_do_not_starve_each_other,
    fs::fs_round_trips,
    fs::search_greps_directories_and_single_files,
    git::git_round_trip,
    git::git_clone_pins_a_tag,
    git::git_ambient_credentials_apply,
    git::git_verbs_report_typed_results,
    honesty::unsupported_actions_say_so,
    lifecycle::pause_resume_cycle,
    lifecycle::fork_preserves_live_process_state,
    honesty::snapshot_modes_are_honest,
    facets::stdio_process_round_trips,
    facets::pty_is_bidirectional,
    facets::logs_follow_streams_and_cancels,
    lifecycle::attach_and_list_by_label,
    lifecycle::create_emits_terminal_events,
    honesty::services_match_capabilities,
    facets::services_wait_for_ports_and_list_them,
    honesty::ssh_access_matches_capabilities,
    honesty::shell_command_access_matches_capabilities,
    honesty::exec_rejects_undeclared_stdin_and_stop,
    fs::fs_range_and_append_round_trip,
    facets::background_services_round_trip,
    lifecycle::provider_health_answers,
    volumes::volume_round_trip,
    facets::one_shot_shares_the_sandbox_world,
    fs::fs_missing_file_is_not_found,
];

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
