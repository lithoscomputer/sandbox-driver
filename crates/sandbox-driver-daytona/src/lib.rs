//! Daytona cloud sandbox provider.
//!
//! VM-backed sandboxes (`Isolation::Vm`) through the Daytona control
//! plane and per-sandbox toolbox daemon, with snapshots and volumes as
//! first-class services and preview-URL/SSH access facets.
//!
//! Lifecycle: archive, undelete (Daytona's "recover" — restore
//! within 24 hours of deletion), refresh-activity, all five timers (TTL
//! and auto-pause included), labels, runtime network updates, and — on
//! VM sandbox classes, narrowed per sandbox — pause/resume, fork, and
//! sandbox-to-snapshot with filesystem and live-process-state modes. The
//! PTY facet rides the toolbox
//! WebSocket; `spawn_stdio` rides command sessions and is UTF-8-only
//! (see the stdio module). The outbound proxy is `provider_config`
//! (`{"outbound_proxy_url": …}`), composing with a domain allow list as
//! upstream intends rather than competing as a network policy. Plain execs run
//! buffered through the toolbox's one-shot endpoint; a sink or stop token
//! routes through a command session, which streams logs live with
//! separated stdout/stderr, kills on stop/timeout by deleting the
//! session, and preserves partial output on timeout. Stdin is delivered
//! through a temp-file redirection inside the sandbox on both paths.
//! Git follows Fabro's hybrid path: clone uses the native toolbox API;
//! worktree and remote operations use the shared exec-derived implementation.
//! Daytona derives Search and background-service management through exec.
//! Snapshots used with these facets must therefore provide the commands
//! documented by [`sandbox_driver::Search`] and [`sandbox_driver::Services`],
//! plus `git`, on `PATH`.
//! Resize remains in the normalized interface, but the current hosted
//! Daytona API and official SDK do not expose a working resize route, so
//! this provider does not declare it.
//!
//! # Lifecycle timers
//!
//! Unset timers inherit Daytona's server defaults — notably auto-stop
//! after **15 idle minutes**, which is shorter than a single long
//! inference call. Callers that run long commands should set
//! `timers.auto_stop_after_idle` explicitly. `Duration::ZERO` is the
//! explicit "never", encoded per timer: wire `0` disables auto-stop;
//! auto-delete crosses as `-1` (its wire `0` means delete immediately
//! on stop and is reserved for the ephemeral flag); auto-archive
//! crosses as `0`, which Daytona reads as "the maximum interval" — the
//! closest the API comes to disabling it.
//!
//! # Configuration
//!
//! [`DaytonaProvider::connect`] uses the SDK's environment configuration:
//! `DAYTONA_API_KEY` (or `DAYTONA_JWT_TOKEN` + `DAYTONA_ORGANIZATION_ID`),
//! optional `DAYTONA_API_URL` and `DAYTONA_TARGET`.
//! [`DaytonaProvider::connect_with_config`] accepts the same values explicitly,
//! so an embedding application can pass vault-resolved credentials without
//! changing the process environment.

mod access;
mod docker_transport;
mod exec;
mod fs;
mod git;
mod logs;
mod nested_docker;
mod pty;
mod session;
mod stdio;

use std::collections::{BTreeMap, HashMap};
use std::fmt::Debug;
use std::result::Result as StdResult;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use daytona_api_client::apis::{Error as ApiError, sandbox_api, snapshots_api};
use daytona_api_client::models::api_key_list::Permissions;
use daytona_api_client::models::sandbox::SandboxClass as DaytonaSandboxClass;
use daytona_api_client::models::snapshot_dto::SandboxClass as DaytonaSnapshotClass;
use daytona_api_client::models::{
    CreateSandboxSnapshot, SandboxClass as DaytonaCreateSandboxClass, SnapshotDto,
    SnapshotState as ApiSnapshotState, UpdateSandboxNetworkSettings, VolumeDto,
    VolumeState as ApiVolumeState,
};
pub use daytona_sdk::DaytonaConfig;
use daytona_sdk::{
    Client, CreateParams, CreateSandboxOptions, CreateSnapshotParams, DaytonaError, DockerImage,
    ImageParams, ImageSource, SandboxBaseParams, SetFilePermissionsOptions, SnapshotParams,
};
use sandbox_driver::{
    Action, AuthError, Capabilities, Capability, Error, EventContext, EventEmitter, EventSubject,
    Exec, ExecFailure, ExecSpec, Filesystem, ForkOptions, Git, HealthStatus, Isolation,
    LifecycleTimers, LogSink, Logs, LogsCaps, NetworkPolicy, OneShot, PlatformInfo, PreviewUrls,
    ProviderError, ProviderHealth, ProviderKind, Pty, PtyCaps, ResourceKind, Resources, Result,
    Sandbox, SandboxFilter, SandboxId, SandboxKind, SandboxProvider, SandboxSnapshotOptions,
    SandboxSource, SandboxSpec, SandboxState, SandboxStatus, SnapshotCaps, SnapshotFilter,
    SnapshotId, SnapshotMode, SnapshotProvider, SnapshotSource, SnapshotSpec, SnapshotState,
    SnapshotStatus, SshAccess, Vnc, VolumeCaps, VolumeId, VolumeProvider, VolumeSpec, VolumeState,
    VolumeStatus, WebTerminal,
};
pub use sandbox_driver_daytona_config::{
    DaytonaProviderConfig, DockerExecutionTarget, NestedDockerConfig,
};
use serde::Deserialize;
use tokio::time;

pub use crate::access::DaytonaAccess;
pub use crate::exec::DaytonaExec;
pub use crate::fs::DaytonaFs;
pub use crate::git::DaytonaGit;
pub use crate::logs::DaytonaLogs;
use crate::nested_docker::NestedDocker;
pub use crate::pty::DaytonaPty;

const MANAGED_LABEL: &str = "sh.sandbox-driver.managed";
const WORKING_DIRECTORY_LABEL: &str = "sh.sandbox-driver.working-directory";
const FALLBACK_WORKING_DIR: &str = "/home/daytona";
const RUNTIME_DIRECTORY_PARENT: &str = "/tmp/sandbox-driver";
const RUNTIME_DIRECTORY: &str = "/tmp/sandbox-driver/runtime";
const CREATE_TIMEOUT: Duration = Duration::from_secs(600);
/// Dockerfile sources build the image during create; real builds exceed
/// shorter budgets (fabro-sandbox landed on 30 minutes).
const DOCKERFILE_CREATE_TIMEOUT: Duration = Duration::from_secs(1800);
const CREATE_POLL: Duration = Duration::from_secs(2);
/// Upper bound on cleanup calls (deletes) so a stalled REST call cannot
/// block cancellation or failure paths indefinitely.
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(10);
/// Budget for waiting out an in-flight Daytona lifecycle transition
/// (for example an auto-stop racing a reactivation).
const TRANSITION_BUDGET: Duration = Duration::from_secs(120);
const TRANSITION_POLL: Duration = Duration::from_secs(1);
const SNAPSHOT_ACTIVATE_BUDGET: Duration = Duration::from_secs(900);
const SNAPSHOT_ACTIVATE_POLL: Duration = Duration::from_secs(5);

/// The current-key endpoint includes its effective organization, which the
/// generated SDK model currently discards. Read only health metadata here;
/// neither the credential nor its masked value belongs in provider identity.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CurrentApiKey {
    name:            String,
    permissions:     Vec<Permissions>,
    #[serde(default)]
    organization_id: Option<String>,
}

/// Items requested per page when listing sandboxes or snapshots. The
/// paginated endpoints truncate an unpaged request to their own default
/// page size, so listings must walk `total_pages` explicitly.
const LIST_PAGE_SIZE: i32 = 100;

fn is_internal_label(key: &str) -> bool {
    matches!(
        key,
        MANAGED_LABEL | WORKING_DIRECTORY_LABEL | nested_docker::TARGET_LABEL
    )
}

/// The labels Daytona stores for a sandbox: the caller's, minus anything
/// that would spoof internal metadata, plus the internal set itself. Both
/// `create` and `set_labels` build them here, so replacing a sandbox's
/// labels cannot drop the nested-Docker target and demote it to a plain
/// VM on the next attach.
fn stored_labels(
    caller: &BTreeMap<String, String>,
    working_directory: Option<&str>,
    docker_target: Option<DockerExecutionTarget>,
) -> HashMap<String, String> {
    let mut labels: HashMap<String, String> = caller
        .iter()
        .filter(|(key, _)| !is_internal_label(key))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    labels.insert(MANAGED_LABEL.to_owned(), "true".to_owned());
    if let Some(working_directory) = working_directory {
        labels.insert(
            WORKING_DIRECTORY_LABEL.to_owned(),
            working_directory.to_owned(),
        );
    }
    if let Some(target) = docker_target {
        labels.insert(
            nested_docker::TARGET_LABEL.to_owned(),
            nested_docker::target_label(target).to_owned(),
        );
    }
    labels
}

/// Scopes every sandbox-driver Daytona operation may need, paired with
/// their wire names for [`ProviderHealth::missing_permissions`].
const REQUIRED_PERMISSIONS: &[(Permissions, &str)] = &[
    (Permissions::WRITE_SANDBOXES, "write:sandboxes"),
    (Permissions::DELETE_SANDBOXES, "delete:sandboxes"),
    (Permissions::WRITE_SNAPSHOTS, "write:snapshots"),
    (Permissions::DELETE_SNAPSHOTS, "delete:snapshots"),
];

pub(crate) type DaytonaClient = Arc<Client>;

pub(crate) fn shell_quote(value: &str) -> String {
    let mut quoted = String::with_capacity(value.len() + 2);
    quoted.push('\'');
    for c in value.chars() {
        if c == '\'' {
            quoted.push_str("'\\''");
        } else {
            quoted.push(c);
        }
    }
    quoted.push('\'');
    quoted
}

/// `exec env KEY=VALUE… program args…` as one shell word list, each word
/// single-quoted. The toolbox API takes a shell string, so this is the one
/// place the exec contract's argv is turned back into shell — and the
/// quoting is what keeps it literal. The environment rides on `env`
/// rather than `export` so that names which are not shell identifiers
/// (`INPUT_INCLUDE-HIDDEN-FILES`) reach the program too.
pub(crate) fn exec_line(env: &BTreeMap<String, String>, program: &str, args: &[String]) -> String {
    let mut line = String::from("exec env");
    for (key, value) in env {
        line.push(' ');
        line.push_str(&shell_quote(&format!("{key}={value}")));
    }
    line.push(' ');
    line.push_str(&shell_quote(program));
    for arg in args {
        line.push(' ');
        line.push_str(&shell_quote(arg));
    }
    line
}

pub(crate) fn is_not_found(error: &DaytonaError) -> bool {
    matches!(error, DaytonaError::NotFound { .. })
}

/// The toolbox reports a command that exceeded its server-side timeout as
/// a 408.
pub(crate) fn is_server_timeout(error: &DaytonaError) -> bool {
    matches!(error, DaytonaError::Api {
        status_code: 408,
        ..
    })
}

/// A lifecycle action racing an in-flight state change: Daytona rejects
/// it with "Sandbox state change in progress" — HTTP 400 in observed
/// traffic (409 accepted defensively). For an idempotent action that
/// means wait for the transition to settle and re-check, never fail.
pub(crate) fn is_state_change_in_progress(error: &DaytonaError) -> bool {
    matches!(
        error,
        DaytonaError::Api {
            status_code: 400 | 409,
            message,
            ..
        } if message.to_lowercase().contains("state change in progress")
    )
}

fn is_snapshot_deactivation_in_progress(error: &DaytonaError) -> bool {
    matches!(
        error,
        DaytonaError::Api {
            status_code: 400,
            message,
            ..
        } if message.to_lowercase().contains("deactivation is still in progress")
    )
}

/// Maps a generated-client error for the few control-plane endpoints the
/// wrapped SDK does not cover (snapshot deactivation, API-key
/// introspection).
fn generated_error<T>(context: &str, error: ApiError<T>) -> Error
where
    T: Debug + Send + Sync + 'static,
{
    let kind = ProviderKind::try_new("daytona").expect("static kind is valid");
    let status = match &error {
        ApiError::ResponseError(content) => Some(content.status),
        _ => None,
    };
    let mut provider = ProviderError::with_source(kind, context, error);
    if let Some(status) = status {
        provider.code = Some(status.as_u16().to_string());
        provider.retryable = status.is_server_error();
    }
    Error::Provider(provider)
}

fn is_generated_not_found<T>(error: &ApiError<T>) -> bool {
    matches!(error, ApiError::ResponseError(content) if content.status.as_u16() == 404)
}

/// The console page listing sandboxes, derived from the API base path —
/// the hosted control plane serves the API under `/api` next to the
/// dashboard. A differently shaped deployment gets no link rather than
/// a guessed one.
fn dashboard_url(client: &daytona_sdk::Client) -> Option<String> {
    client
        .api_configuration()
        .base_path
        .strip_suffix("/api")
        .map(|base| format!("{base}/dashboard/sandboxes"))
}

pub(crate) fn daytona_error(context: &str, error: DaytonaError) -> Error {
    let kind = ProviderKind::try_new("daytona").expect("static kind is valid");
    if let DaytonaError::RateLimit { headers, .. } = &error {
        let retry_after = headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("retry-after"))
            .and_then(|(_, value)| value.parse::<u64>().ok())
            .map(Duration::from_secs);
        return Error::RateLimited { retry_after };
    }
    if matches!(&error, DaytonaError::Api {
        status_code: 401 | 403,
        ..
    }) {
        return Error::Auth(AuthError::with_source(kind, context, error));
    }

    let status_code = error.status_code();
    let timed_out = matches!(&error, DaytonaError::Timeout { .. });
    let mut provider = ProviderError::with_source(kind, context, error);
    if let Some(status_code) = status_code {
        provider.code = Some(status_code.to_string());
        provider.retryable = status_code >= 500;
    } else if timed_out {
        provider.code = Some("timeout".to_owned());
        // A request timeout does not prove the remote operation stopped:
        // retrying a clone whose first attempt is still writing the
        // target overlaps it (fabro never retried timeouts for exactly
        // this reason). Callers judge idempotent retries themselves.
        provider.retryable = false;
    }
    Error::Provider(provider)
}

fn map_state(state: Option<daytona_sdk::SandboxState>) -> SandboxState {
    use daytona_sdk::SandboxState as Ds;
    match state {
        None => SandboxState::Unknown,
        Some(state) => match state {
            Ds::Creating | Ds::PendingBuild | Ds::BuildingSnapshot | Ds::PullingSnapshot => {
                SandboxState::Creating
            }
            Ds::Restoring | Ds::Starting => SandboxState::Starting,
            // A snapshotting sandbox stays fully usable (fabro mapped it
            // to Running deliberately); reporting it transitional makes
            // activation and waits stall through a multi-minute snapshot.
            // The raw string still reaches callers via provider_state.
            Ds::Started | Ds::Snapshotting => SandboxState::Running,
            Ds::Stopping => SandboxState::Stopping,
            Ds::Stopped => SandboxState::Stopped,
            Ds::Archiving => SandboxState::Archiving,
            Ds::Archived => SandboxState::Archived,
            Ds::Resizing => SandboxState::Resizing,
            Ds::Forking => SandboxState::Forking,
            Ds::Pausing => SandboxState::Pausing,
            Ds::Paused => SandboxState::Paused,
            Ds::Resuming => SandboxState::Resuming,
            Ds::Destroying => SandboxState::Deleting,
            Ds::Destroyed => SandboxState::Deleted,
            Ds::Error | Ds::BuildFailed => SandboxState::Error,
            Ds::Unknown | Ds::UnknownDefaultOpenApi => SandboxState::Unknown,
        },
    }
}

fn generated_snapshot_name() -> String {
    format!(
        "sandbox-driver-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_secs())
    )
}

async fn create_sandbox_snapshot(
    client: &DaytonaClient,
    sandbox_id: &str,
    name: &str,
    mode: SnapshotMode,
) -> Result<SnapshotId> {
    let sdk = client
        .get(sandbox_id)
        .await
        .map_err(|error| daytona_error("fetching sandbox for snapshot", error))?;
    let current = map_state(sdk.state);
    let required = match mode {
        SnapshotMode::Filesystem => SandboxState::Stopped,
        SnapshotMode::LiveProcessState => SandboxState::Running,
        _ => {
            return Err(Error::invalid_spec(
                "mode",
                "unsupported sandbox snapshot mode",
            ));
        }
    };
    if current != required {
        return Err(Error::InvalidState {
            current,
            action: Action::Snapshot,
        });
    }

    let request = CreateSandboxSnapshot {
        name:           name.to_owned(),
        include_memory: Some(mode == SnapshotMode::LiveProcessState),
    };
    sandbox_api::create_sandbox_snapshot(
        client.api_configuration(),
        sandbox_id,
        request,
        client.organization_id(),
    )
    .await
    .map_err(|error| generated_error("snapshotting sandbox", error))?;

    // Wait on the snapshot record itself, not the sandbox state: right
    // after the POST the sandbox may not have entered Snapshotting yet,
    // so watching it can declare completion while the snapshot is still
    // being written — and a caller could delete the sandbox under it.
    let started = Instant::now();
    loop {
        match client.snapshot.get(name).await {
            // The record can appear a beat after the POST.
            Err(error) if is_not_found(&error) => {}
            Err(error) => {
                return Err(daytona_error("waiting for sandbox snapshot", error));
            }
            Ok(dto) => match map_snapshot_state(dto.state) {
                // Inactive counts as written: the org's active-snapshot
                // budget can deactivate a snapshot on arrival, but the
                // data exists and activate() can bring it back.
                SnapshotState::Active | SnapshotState::Inactive => {
                    return SnapshotId::try_new(dto.id)
                        .map_err(|error| Error::invalid_spec("snapshot_id", error.to_string()));
                }
                SnapshotState::Error => {
                    return Err(Error::Provider(ProviderError::new(
                        ProviderKind::try_new("daytona").expect("static kind is valid"),
                        dto.error_reason
                            .unwrap_or_else(|| "sandbox snapshot failed".to_owned()),
                    )));
                }
                SnapshotState::Deleting => {
                    return Err(Error::Provider(ProviderError::new(
                        ProviderKind::try_new("daytona").expect("static kind is valid"),
                        "snapshot was removed while being created".to_owned(),
                    )));
                }
                // Building — or a state this crate does not know yet:
                // keep polling; the budget below bounds the wait.
                _ => {}
            },
        }
        let elapsed = started.elapsed();
        if elapsed >= CREATE_TIMEOUT {
            return Err(Error::Timeout {
                operation: "snapshotting sandbox".to_owned(),
                elapsed,
            });
        }
        time::sleep(TRANSITION_POLL).await;
    }
}

async fn created_snapshot_id(client: &DaytonaClient, name: &str) -> Result<SnapshotId> {
    let dto = client
        .snapshot
        .get(name)
        .await
        .map_err(|error| daytona_error("fetching created snapshot", error))?;
    SnapshotId::try_new(dto.id)
        .map_err(|error| Error::invalid_spec("snapshot_id", error.to_string()))
}

fn sandbox_kind_from_sandbox_class(class: DaytonaSandboxClass) -> SandboxKind {
    match class {
        DaytonaSandboxClass::CONTAINER => SandboxKind::Container,
        DaytonaSandboxClass::LINUX_VM
        | DaytonaSandboxClass::ANDROID
        | DaytonaSandboxClass::WINDOWS => SandboxKind::VirtualMachine,
        DaytonaSandboxClass::UnknownDefaultOpenApi => SandboxKind::Unknown,
    }
}

fn sandbox_kind_from_snapshot_class(class: DaytonaSnapshotClass) -> SandboxKind {
    match class {
        DaytonaSnapshotClass::CONTAINER => SandboxKind::Container,
        DaytonaSnapshotClass::LINUX_VM
        | DaytonaSnapshotClass::ANDROID
        | DaytonaSnapshotClass::WINDOWS => SandboxKind::VirtualMachine,
        DaytonaSnapshotClass::UnknownDefaultOpenApi => SandboxKind::Unknown,
    }
}

fn daytona_snapshot_class(kind: SandboxKind) -> Result<DaytonaCreateSandboxClass> {
    match kind {
        SandboxKind::Container => Ok(DaytonaCreateSandboxClass::CONTAINER),
        SandboxKind::VirtualMachine => Ok(DaytonaCreateSandboxClass::LINUX_VM),
        _ => Err(Error::invalid_spec("sandbox_kind", "unknown sandbox kind")),
    }
}

fn status_from_sdk(
    client: &daytona_sdk::Client,
    sdk: &daytona_sdk::Sandbox,
) -> Result<SandboxStatus> {
    let id = SandboxId::try_new(&sdk.id)
        .map_err(|error| Error::invalid_spec("sandbox_id", error.to_string()))?;
    let mut status = SandboxStatus::new(id, map_state(sdk.state));
    status.name = (!sdk.name.is_empty()).then(|| sdk.name.clone());
    status.provider_state = sdk.state.map(|state| state.to_string()).unwrap_or_default();
    status.error_reason.clone_from(&sdk.error_reason);
    status.sandbox_kind = sdk.sandbox_class.map(sandbox_kind_from_sandbox_class);
    status.region = (!sdk.target.is_empty()).then(|| sdk.target.clone());
    status.labels = sdk
        .labels
        .iter()
        .filter(|(key, _)| !is_internal_label(key))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    status.source.clone_from(&sdk.snapshot);
    status.web_url = dashboard_url(client);
    let mut resources = Resources::default();
    resources.cpu_cores = to_u64(sdk.cpu)
        .and_then(|cpu| u32::try_from(cpu).ok())
        .filter(|cpu| *cpu > 0);
    resources.memory_mb = to_u64(sdk.memory * 1024.0).filter(|mb| *mb > 0);
    resources.disk_mb = to_u64(sdk.disk * 1024.0).filter(|mb| *mb > 0);
    resources.gpus = to_u64(sdk.gpu)
        .and_then(|gpu| u32::try_from(gpu).ok())
        .filter(|gpu| *gpu > 0);
    status.resources = Some(resources);
    Ok(status)
}

/// Converts a non-negative float to `u64`, `None` when out of range.
#[expect(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "guarded by the range check"
)]
fn to_u64(value: f64) -> Option<u64> {
    (value.is_finite() && value >= 0.0 && value < u64::MAX as f64).then(|| value.round() as u64)
}

/// Converts a timer duration to Daytona's whole-minute intervals,
/// rounding up so a sub-minute timer never truncates away. Wire `0`
/// (from `Duration::ZERO`) is deliberate and timer-specific: it
/// disables auto-stop, and defers auto-archive to Daytona's maximum
/// interval — the closest the API comes to disabling it.
fn minutes(duration: Duration) -> i32 {
    if duration.is_zero() {
        return 0;
    }
    i32::try_from(duration.as_secs().div_ceil(60)).unwrap_or(i32::MAX)
}

/// Auto-delete has inverted zero semantics on the wire: `0` means
/// "delete immediately upon stopping" (the ephemeral encoding, sent
/// only via the spec flag) and a negative value disables — so
/// `Duration::ZERO`, the crate-wide explicit "never", crosses as `-1`.
fn auto_delete_minutes(duration: Duration) -> i32 {
    if duration.is_zero() {
        return -1;
    }
    minutes(duration)
}

fn gigabytes(mb: u64) -> i32 {
    i32::try_from(mb.div_ceil(1024)).unwrap_or(i32::MAX).max(1)
}

/// The Daytona provider.
pub struct DaytonaProvider {
    kind:         ProviderKind,
    capabilities: Capabilities,
    client:       DaytonaClient,
    snapshots:    DaytonaSnapshots,
    volumes:      DaytonaVolumes,
}

impl DaytonaProvider {
    /// Connects using the SDK's environment configuration.
    #[tracing::instrument(skip_all, fields(provider_kind = "daytona"), err)]
    pub async fn connect() -> Result<Self> {
        let client = Client::new()
            .await
            .map_err(|error| daytona_error("connecting to daytona", error))?;
        Ok(Self::from_client(client))
    }

    /// Connects using explicit SDK configuration.
    ///
    /// Values set in `config` take precedence over the SDK's environment
    /// variables. Unset values retain the SDK's environment fallbacks.
    ///
    /// # Errors
    ///
    /// Returns an error when the configuration is invalid or the SDK client
    /// cannot be initialized.
    #[tracing::instrument(skip_all, fields(provider_kind = "daytona"), err)]
    pub async fn connect_with_config(config: DaytonaConfig) -> Result<Self> {
        let client = Client::new_with_config(config)
            .await
            .map_err(|error| daytona_error("connecting to daytona", error))?;
        Ok(Self::from_client(client))
    }

    fn from_client(client: Client) -> Self {
        let client = Arc::new(client);
        let kind = ProviderKind::try_new("daytona").expect("static kind is valid");
        Self {
            kind: kind.clone(),
            capabilities: daytona_capabilities(),
            snapshots: DaytonaSnapshots {
                client: Arc::clone(&client),
                kind:   kind.clone(),
            },
            volumes: DaytonaVolumes {
                client: Arc::clone(&client),
                kind,
            },
            client,
        }
    }

    /// Creates the sandbox and waits for it to start under `budget`,
    /// deleting the half-created (and billed) sandbox when the wait
    /// fails so nothing is silently leaked.
    #[tracing::instrument(skip_all, fields(provider_kind = %self.kind), err)]
    async fn create_inner(
        &self,
        params: CreateParams,
        budget: Duration,
    ) -> Result<daytona_sdk::Sandbox> {
        let options = CreateSandboxOptions {
            timeout:        Some(budget),
            wait_for_start: false,
            log_sender:     None,
        };
        let created = self
            .client
            .create(params, options)
            .await
            .map_err(|error| daytona_error("creating sandbox", error))?;
        let sdk_id = created.id.clone();
        match self.wait_for_started(&sdk_id, budget).await {
            Ok(sdk) => Ok(sdk),
            Err(error) => Err(self.cleanup_failed_create(&sdk_id, error).await),
        }
    }

    async fn wait_for_started(
        &self,
        sdk_id: &str,
        budget: Duration,
    ) -> Result<daytona_sdk::Sandbox> {
        let started = Instant::now();
        let mut attempt = 0_u64;
        loop {
            attempt += 1;
            let sdk = self
                .client
                .get(sdk_id)
                .await
                .map_err(|error| daytona_error("fetching created sandbox", error))?;
            let state = map_state(sdk.state);
            tracing::debug!(attempt, state = ?state, "sandbox create state observed");
            match state {
                SandboxState::Running => return Ok(sdk),
                SandboxState::Error => {
                    return Err(Error::Provider(ProviderError::new(
                        self.kind.clone(),
                        sdk.error_reason
                            .unwrap_or_else(|| "sandbox entered the error state".to_owned()),
                    )));
                }
                _ => {}
            }
            let elapsed = started.elapsed();
            if elapsed >= budget {
                return Err(Error::Timeout {
                    operation: "creating sandbox".to_owned(),
                    elapsed,
                });
            }
            time::sleep(CREATE_POLL).await;
        }
    }

    /// Best-effort delete of a sandbox left behind by a failed create,
    /// bounded by [`CLEANUP_TIMEOUT`]. When the delete itself fails, the
    /// id is surfaced in the returned error so the caller can clean up
    /// later.
    async fn cleanup_failed_create(&self, sdk_id: &str, cause: Error) -> Error {
        match time::timeout(CLEANUP_TIMEOUT, self.client.delete(sdk_id)).await {
            Ok(Ok(())) => cause,
            Ok(Err(error)) if is_not_found(&error) => cause,
            _ => Error::Provider(ProviderError::with_source(
                self.kind.clone(),
                format!("failed create left sandbox {sdk_id} behind"),
                cause,
            )),
        }
    }

    async fn handle(
        &self,
        sdk: daytona_sdk::Sandbox,
        events: EventEmitter,
    ) -> Result<Arc<DaytonaSandbox>> {
        build_handle(&self.client, &self.capabilities, sdk, events).await
    }

    async fn ensure_snapshot_kind(
        &self,
        id: &SnapshotId,
        requested: Option<SandboxKind>,
    ) -> Result<()> {
        let Some(requested) = requested else {
            return Ok(());
        };
        let snapshot = self
            .client
            .snapshot
            .get(id.as_str())
            .await
            .map_err(|error| {
                if is_not_found(&error) {
                    Error::NotFound {
                        resource: ResourceKind::Snapshot,
                        id:       id.as_str().to_owned(),
                    }
                } else {
                    daytona_error("fetching snapshot kind", error)
                }
            })?;
        let Some(actual) = snapshot.sandbox_class.map(sandbox_kind_from_snapshot_class) else {
            return Err(Error::invalid_spec(
                "sandbox_kind",
                "the snapshot does not report a sandbox kind",
            ));
        };
        if actual != requested {
            return Err(Error::invalid_spec(
                "sandbox_kind",
                format!("the snapshot has kind {actual:?}, not {requested:?}"),
            ));
        }
        Ok(())
    }
}

/// Builds a sandbox handle from an SDK sandbox, narrowing the capability
/// set by sandbox class. Shared by the provider (create/attach/undelete)
/// and by `fork`, which builds the child's handle from an existing one.
async fn build_handle(
    client: &DaytonaClient,
    base_capabilities: &Capabilities,
    sdk: daytona_sdk::Sandbox,
    events: EventEmitter,
) -> Result<Arc<DaytonaSandbox>> {
    let working_dir = match sdk.labels.get(WORKING_DIRECTORY_LABEL) {
        Some(dir) => dir.clone(),
        None => match sdk.get_working_dir().await {
            Ok(dir) => dir,
            // A stopped sandbox has no reachable toolbox; legacy sandboxes
            // have no stored requested directory, so use the conventional
            // home until the next attach while running.
            Err(_) => FALLBACK_WORKING_DIR.to_owned(),
        },
    };
    let id = SandboxId::try_new(&sdk.id)
        .map_err(|error| Error::invalid_spec("sandbox_id", error.to_string()))?;
    let nested = sdk
        .labels
        .get(nested_docker::TARGET_LABEL)
        .map(|label| {
            nested_docker::parse_target(label)
                .map(|target| NestedDocker::new(client, &sdk.id, &working_dir, target))
        })
        .transpose()?;
    let mut capabilities = narrowed_capabilities(base_capabilities, sdk.sandbox_class);
    capabilities.one_shot = None;
    capabilities.exec.stdin_stream = false;
    if let Some(nested) = &nested {
        nested.capabilities(&mut capabilities);
    }
    Ok(Arc::new(DaytonaSandbox {
        exec: DaytonaExec::new(Arc::clone(client), sdk.id.clone(), working_dir.clone()),
        git: DaytonaGit::new(Arc::clone(client), sdk.id.clone(), working_dir.clone()),
        fs: DaytonaFs::new(Arc::clone(client), sdk.id.clone(), working_dir.clone()),
        access: DaytonaAccess::new(Arc::clone(client), sdk.id.clone()),
        logs: DaytonaLogs::new(Arc::clone(client), sdk.id.clone()),
        pty: DaytonaPty::new(Arc::clone(client), sdk.id.clone(), working_dir.clone()),
        id,
        name: (!sdk.name.is_empty()).then(|| sdk.name.clone()),
        capabilities,
        client: Arc::clone(client),
        sdk_id: sdk.id,
        working_dir,
        nested,
        events,
    }))
}

async fn initialize_directories(
    sdk: &daytona_sdk::Sandbox,
    working_directory: Option<&str>,
) -> Result<()> {
    let fs = sdk
        .fs()
        .await
        .map_err(|error| daytona_error("connecting to the toolbox", error))?;
    if let Some(working_directory) = working_directory {
        fs.create_folder(working_directory, Some("0755"))
            .await
            .map_err(|error| daytona_error("creating requested working directory", error))?;
    }
    for path in [RUNTIME_DIRECTORY_PARENT, RUNTIME_DIRECTORY] {
        fs.create_folder(path, Some("0700"))
            .await
            .map_err(|error| daytona_error("creating runtime directory", error))?;
        fs.set_file_permissions(path, SetFilePermissionsOptions {
            mode:  Some("0700".to_owned()),
            owner: None,
            group: None,
        })
        .await
        .map_err(|error| daytona_error("setting runtime directory permissions", error))?;
    }
    Ok(())
}

fn daytona_capabilities() -> Capabilities {
    let mut caps = Capabilities::minimal(Isolation::Vm);
    caps.lifecycle.archive = true;
    // VM-class-only verbs are declared at the provider level (the upper
    // bound); the per-sandbox set narrows them by class.
    caps.lifecycle.pause = true;
    caps.lifecycle.fork = true;
    caps.lifecycle.snapshot_sandbox = true;
    // Daytona's "recover" endpoint is an undelete (restore within 24
    // hours of deletion), not recovery from the Error state.
    caps.lifecycle.undelete = true;
    caps.lifecycle.resize = false;
    caps.lifecycle.refresh_activity = true;
    caps.lifecycle.timers = true;
    caps.lifecycle.labels = true;
    caps.lifecycle.update_network = true;
    caps.exec.stdin = true;
    caps.exec.stop = true;
    caps.exec.live_streaming = true;
    caps.exec.streams_separated = true;
    // Session-backed; UTF-8 payloads only (the ACP use case) — see the
    // stdio module.
    caps.exec.stdio_process = true;
    caps.exec.environment = true;
    caps.exec.stdin_stream = true;
    caps.one_shot = sandbox_driver_docker::docker_capabilities().one_shot;
    caps.fs.native = true;
    caps.fs.upload = true;
    caps.fs.download = true;
    caps.fs.permissions = true;
    caps.search.supported = true;
    caps.git.supported = true;
    caps.git.native = true;
    caps.services.supported = true;
    caps.pty = Some({
        let mut pty = PtyCaps::default();
        pty.resize = true;
        pty
    });
    caps.logs = Some({
        let mut logs = LogsCaps::default();
        logs.entrypoint = true;
        logs
    });
    caps.access.preview_urls = true;
    caps.access.signed_preview_urls = true;
    caps.access.ssh = true;
    caps.access.ssh_ttl = true;
    caps.access.ssh_revoke = true;
    caps.access.web_terminal = true;
    caps.access.vnc = true;
    caps.network.allow_all = true;
    caps.network.block_all = true;
    caps.network.cidr_allow_list = true;
    caps.network.domain_allow_list = true;
    caps.snapshots = Some({
        let mut snapshots = SnapshotCaps::default();
        snapshots.from_image = true;
        snapshots.from_dockerfile = true;
        snapshots.from_image_kinds.container = true;
        snapshots.from_image_kinds.virtual_machine = true;
        snapshots.from_dockerfile_kinds.container = true;
        snapshots.filesystem_from_sandbox = true;
        snapshots.live_process_state_from_sandbox = true;
        snapshots.build_logs = true;
        snapshots.activation = true;
        snapshots
    });
    caps.volumes = Some({
        let mut volumes = VolumeCaps::default();
        volumes.create_time_attach = true;
        volumes
    });
    caps
}

/// Narrows the provider's upper-bound capability set to one sandbox.
///
/// Pause and fork are VM-class operations; archive is a container-class
/// operation. Live snapshots are supported on the hosted default sandbox
/// class and remain declared. An unknown or unreported class keeps the
/// upper bound — the typed `Unsupported`/provider error at the call is
/// still the enforcement.
fn narrowed_capabilities(base: &Capabilities, class: Option<DaytonaSandboxClass>) -> Capabilities {
    let mut caps = base.clone();
    if matches!(
        class,
        Some(DaytonaSandboxClass::CONTAINER | DaytonaSandboxClass::ANDROID)
    ) {
        caps.lifecycle.pause = false;
        caps.lifecycle.fork = false;
        if let Some(snapshots) = &mut caps.snapshots {
            snapshots.live_process_state_from_sandbox = false;
        }
    }
    if matches!(
        class,
        Some(
            DaytonaSandboxClass::LINUX_VM
                | DaytonaSandboxClass::ANDROID
                | DaytonaSandboxClass::WINDOWS
        )
    ) {
        caps.lifecycle.archive = false;
    }
    caps
}

fn provider_config(value: &serde_json::Value) -> Result<DaytonaProviderConfig> {
    match value {
        serde_json::Value::Null => Ok(DaytonaProviderConfig::default()),
        serde_json::Value::Object(_) => DaytonaProviderConfig::deserialize(value)
            .map_err(|error| Error::invalid_spec("provider_config", error.to_string())),
        _ => Err(Error::invalid_spec("provider_config", "expected an object")),
    }
}

fn base_params(spec: &SandboxSpec) -> Result<SandboxBaseParams> {
    let config = provider_config(&spec.provider_config)?;
    let (network_block_all, network_allow_list, domain_allow_list) = match &spec.network {
        NetworkPolicy::ProviderDefault => (None, None, None),
        NetworkPolicy::AllowAll => (Some(false), None, None),
        NetworkPolicy::Block => (Some(true), None, None),
        NetworkPolicy::CidrAllowList { cidrs } => (None, Some(cidrs.clone()), None),
        NetworkPolicy::DomainAllowList { domains } => (None, None, Some(domains.clone())),
        _ => return Err(Error::invalid_spec("network", "unsupported network policy")),
    };
    if let Some(docker) = &config.docker {
        nested_docker::validate(docker, spec)?;
    }
    let labels = stored_labels(
        &spec.labels,
        spec.working_directory.as_deref(),
        config.docker.as_ref().map(|docker| docker.target),
    );
    Ok(SandboxBaseParams {
        name: spec.name.clone(),
        user: spec.user.clone(),
        language: None,
        env_vars: Some({
            let mut env: HashMap<String, String> = spec
                .env
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();
            // Blank BASH_ENV in the sandbox's own environment, overriding
            // any caller or snapshot value. The per-exec strip is not
            // enough: the inner bash of every session exec sources
            // $BASH_ENV at startup, before the stripped script runs.
            env.insert("BASH_ENV".to_owned(), String::new());
            env
        }),
        labels: Some(labels),
        public: if config.docker.is_some() {
            Some(false)
        } else {
            spec.public
        },
        target: spec.region.clone(),
        auto_stop_interval: spec.timers.auto_stop_after_idle.map(minutes),
        auto_pause_interval: spec.timers.auto_pause_after_idle.map(minutes),
        auto_archive_interval: spec.timers.auto_archive_after_stop.map(minutes),
        auto_delete_interval: spec
            .timers
            .auto_delete_after_stop
            .map(auto_delete_minutes)
            .or(if spec.ephemeral { Some(0) } else { None }),
        ttl_minutes: spec.timers.ttl.map(minutes),
        volumes: (!spec.volumes.is_empty()).then(|| {
            spec.volumes
                .iter()
                .map(|mount| daytona_sdk::VolumeMount {
                    volume_id:  mount.volume.clone(),
                    mount_path: mount.mount_path.clone(),
                    subpath:    mount.subpath.clone(),
                })
                .collect()
        }),
        network_block_all,
        network_allow_list,
        domain_allow_list,
        outbound_proxy_url: config.outbound_proxy_url,
        ephemeral: spec.ephemeral.then_some(true),
    })
}

fn sdk_resources(resources: &Resources) -> Option<daytona_sdk::Resources> {
    if *resources == Resources::default() {
        return None;
    }
    Some(daytona_sdk::Resources {
        cpu:    resources
            .cpu_cores
            .and_then(|cores| i32::try_from(cores).ok()),
        gpu:    resources.gpus.and_then(|gpus| i32::try_from(gpus).ok()),
        memory: resources.memory_mb.map(gigabytes),
        disk:   resources.disk_mb.map(gigabytes),
    })
}

fn validate_supported_creation_fields(spec: &SandboxSpec) -> Result<()> {
    if matches!(&spec.source, SandboxSource::Snapshot { .. })
        && spec.resources != Resources::default()
    {
        return Err(Error::invalid_spec(
            "resources",
            "a Daytona sandbox created from a snapshot inherits the snapshot resources",
        ));
    }
    Ok(())
}

#[async_trait]
impl SandboxProvider for DaytonaProvider {
    fn kind(&self) -> &ProviderKind {
        &self.kind
    }

    fn capabilities(&self) -> &Capabilities {
        &self.capabilities
    }

    #[tracing::instrument(skip_all, fields(provider_kind = %self.kind), err)]
    async fn create(
        &self,
        spec: &SandboxSpec,
        events: Option<EventContext>,
    ) -> Result<Arc<dyn Sandbox>> {
        spec.validate()?;
        validate_supported_creation_fields(spec)?;
        let base = base_params(spec)?;
        let nested_docker = provider_config(&spec.provider_config)?.docker;
        let params = match &spec.source {
            SandboxSource::Image { reference } => {
                if spec.sandbox_kind == Some(SandboxKind::VirtualMachine) {
                    return Err(Error::invalid_spec(
                        "sandbox_kind",
                        "Daytona virtual machines must be created from a virtual-machine snapshot",
                    ));
                }
                CreateParams::Image(ImageParams {
                    base,
                    image: ImageSource::Name(reference.clone()),
                    resources: sdk_resources(&spec.resources),
                })
            }
            SandboxSource::Dockerfile { content } => {
                if spec.sandbox_kind == Some(SandboxKind::VirtualMachine) {
                    return Err(Error::invalid_spec(
                        "sandbox_kind",
                        "Daytona virtual machines must be created from a virtual-machine snapshot",
                    ));
                }
                CreateParams::Image(ImageParams {
                    base,
                    image: ImageSource::Custom(DockerImage::from_dockerfile(content)),
                    resources: sdk_resources(&spec.resources),
                })
            }
            SandboxSource::Snapshot { id } => {
                self.ensure_snapshot_kind(id, spec.sandbox_kind).await?;
                CreateParams::Snapshot(SnapshotParams {
                    base,
                    snapshot: id.as_str().to_owned(),
                })
            }
            SandboxSource::HostDirectory => {
                return Err(Error::invalid_spec(
                    "source",
                    "the daytona provider needs an image, dockerfile, or snapshot source",
                ));
            }
            _ => return Err(Error::invalid_spec("source", "unsupported sandbox source")),
        };

        let budget = if matches!(spec.source, SandboxSource::Dockerfile { .. }) {
            DOCKERFILE_CREATE_TIMEOUT
        } else {
            CREATE_TIMEOUT
        };
        let emitter = EventEmitter::new(self.kind.clone(), events);
        let handle_emitter = emitter.clone();
        emitter
            .run(
                EventSubject::pending_sandbox(spec.name.clone()),
                Action::Create,
                |reporter| async move {
                    let created = self.create_inner(params, budget).await?;
                    let event_id = SandboxId::try_new(created.id.clone())
                        .map_err(|error| Error::invalid_spec("sandbox_id", error.to_string()))?;
                    reporter.set_subject(EventSubject::sandbox(Some(event_id)));
                    if let Some(requested) = spec.sandbox_kind {
                        let actual = created.sandbox_class.map(sandbox_kind_from_sandbox_class);
                        if actual != Some(requested) {
                            let id = created.id.clone();
                            let error = Error::invalid_spec(
                                "sandbox_kind",
                                format!(
                                    "Daytona created a sandbox with kind {actual:?}, not \
                                     {requested:?}"
                                ),
                            );
                            return Err(self.cleanup_failed_create(&id, error).await);
                        }
                    }
                    if let Err(error) =
                        initialize_directories(&created, spec.working_directory.as_deref()).await
                    {
                        return Err(self.cleanup_failed_create(&created.id, error).await);
                    }
                    let sdk_id = created.id.clone();
                    let handle = match self.handle(created, handle_emitter).await {
                        Ok(handle) => handle,
                        Err(error) => return Err(self.cleanup_failed_create(&sdk_id, error).await),
                    };
                    if let (Some(config), Some(nested)) = (&nested_docker, handle.nested.as_ref()) {
                        if let Err(error) = nested.create(config, &spec.env).await {
                            return Err(self.cleanup_failed_create(&sdk_id, error).await);
                        }
                    }
                    Ok(handle as Arc<dyn Sandbox>)
                },
            )
            .await
    }

    #[tracing::instrument(
        skip_all,
        fields(provider_kind = %self.kind, sandbox_id = %id),
        err
    )]
    async fn attach(
        &self,
        id: &SandboxId,
        events: Option<EventContext>,
    ) -> Result<Arc<dyn Sandbox>> {
        let emitter = EventEmitter::new(self.kind.clone(), events);
        let handle_emitter = emitter.clone();
        emitter
            .run(
                EventSubject::sandbox(Some(id.clone())),
                Action::Attach,
                |_| async move {
                    let sdk = match self.client.get(id.as_str()).await {
                        Ok(sdk) => sdk,
                        Err(error) if is_not_found(&error) => {
                            return Err(Error::NotFound {
                                resource: ResourceKind::Sandbox,
                                id:       id.as_str().to_owned(),
                            });
                        }
                        Err(error) => return Err(daytona_error("fetching sandbox", error)),
                    };
                    if sdk.labels.get(MANAGED_LABEL).map(String::as_str) != Some("true") {
                        return Err(Error::NotFound {
                            resource: ResourceKind::Sandbox,
                            id:       id.as_str().to_owned(),
                        });
                    }
                    Ok(self.handle(sdk, handle_emitter).await? as Arc<dyn Sandbox>)
                },
            )
            .await
    }

    #[tracing::instrument(
        skip_all,
        fields(provider_kind = %self.kind, sandbox_id = %id),
        err
    )]
    async fn undelete(
        &self,
        id: &SandboxId,
        events: Option<EventContext>,
    ) -> Result<Arc<dyn Sandbox>> {
        let emitter = EventEmitter::new(self.kind.clone(), events);
        let handle_emitter = emitter.clone();
        emitter
            .run(
                EventSubject::sandbox(Some(id.clone())),
                Action::Undelete,
                |_| async move {
                    // Daytona names this "recover": a deleted sandbox stays
                    // restorable for 24 hours.
                    let mut sdk = match self.client.get(id.as_str()).await {
                        Ok(sdk) => sdk,
                        Err(error) if is_not_found(&error) => {
                            return Err(Error::NotFound {
                                resource: ResourceKind::Sandbox,
                                id:       id.as_str().to_owned(),
                            });
                        }
                        Err(error) => return Err(daytona_error("fetching sandbox", error)),
                    };
                    if sdk.labels.get(MANAGED_LABEL).map(String::as_str) != Some("true") {
                        return Err(Error::NotFound {
                            resource: ResourceKind::Sandbox,
                            id:       id.as_str().to_owned(),
                        });
                    }
                    sdk.recover()
                        .await
                        .map_err(|error| daytona_error("undeleting sandbox", error))?;
                    let refreshed = self
                        .client
                        .get(id.as_str())
                        .await
                        .map_err(|error| daytona_error("fetching undeleted sandbox", error))?;
                    Ok(self.handle(refreshed, handle_emitter).await? as Arc<dyn Sandbox>)
                },
            )
            .await
    }

    #[tracing::instrument(skip_all, fields(provider_kind = %self.kind), err)]
    async fn health(&self) -> Result<ProviderHealth> {
        // Reachability and credential acceptance: the cheapest
        // authenticated call.
        if let Err(error) = self.client.list(None, Some(1), Some(1)).await {
            tracing::warn!("daytona provider health check failed");
            let status = match &error {
                DaytonaError::Api {
                    status_code: 401 | 403,
                    ..
                } => HealthStatus::Unauthorized,
                _ => HealthStatus::Unreachable,
            };
            let mut health = ProviderHealth::new(status);
            health.message = Some(format!("listing sandboxes failed: {error}"));
            return Ok(health);
        }
        let mut health = ProviderHealth::new(HealthStatus::Ok);
        // JWT authentication requires an explicit organization. A successful
        // authenticated list above verifies access to that namespace.
        health.identity = self
            .client
            .organization_id()
            .map(|id| format!("organization:{id}"));
        // Scope enumeration works only for API-key credentials; a JWT
        // credential proved itself above and skips it, as does a control
        // plane without key introspection.
        let config = self.client.api_configuration();
        let mut request = config
            .client
            .get(format!("{}/api-keys/current", config.base_path));
        if let Some(token) = &config.bearer_access_token {
            request = request.bearer_auth(token);
        }
        if let Some(organization) = self.client.organization_id() {
            request = request.header("X-Daytona-Organization-ID", organization);
        }
        if let Ok(response) = request.send().await
            && let Ok(response) = response.error_for_status()
            && let Ok(key) = response.json::<CurrentApiKey>().await
        {
            // API keys select their organization even when configuration
            // supplies no organization header. The server's value wins.
            if let Some(organization) = key.organization_id.filter(|id| !id.is_empty()) {
                health.identity = Some(format!("organization:{organization}"));
            }
            health.missing_permissions = REQUIRED_PERMISSIONS
                .iter()
                .filter(|(permission, _)| !key.permissions.contains(permission))
                .map(|(_, name)| (*name).to_owned())
                .collect();
            if !health.missing_permissions.is_empty() {
                tracing::warn!(
                    missing_permission_count = health.missing_permissions.len(),
                    "daytona credentials lack required permissions"
                );
                health.status = HealthStatus::Unauthorized;
                health.message = Some(format!("API key {:?} is missing required scopes", key.name));
            }
        }
        Ok(health)
    }

    #[tracing::instrument(
        skip_all,
        fields(provider_kind = %self.kind, label_count = filter.labels.len()),
        err
    )]
    async fn list(&self, filter: &SandboxFilter) -> Result<Vec<SandboxStatus>> {
        let mut labels: HashMap<String, String> = filter
            .labels
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect();
        labels.insert(MANAGED_LABEL.to_owned(), "true".to_owned());
        let mut statuses = Vec::new();
        let mut page_number: i32 = 1;
        loop {
            let page = self
                .client
                .list(Some(&labels), Some(page_number), Some(LIST_PAGE_SIZE))
                .await
                .map_err(|error| daytona_error("listing sandboxes", error))?;
            tracing::debug!(
                page_number,
                item_count = page.items.len(),
                "sandbox page received"
            );
            for item in &page.items {
                statuses.push(status_from_sdk(&self.client, item)?);
            }
            if page.total_pages <= i64::from(page_number) {
                break;
            }
            page_number += 1;
        }
        Ok(statuses)
    }

    fn snapshots(&self) -> Option<&dyn SnapshotProvider> {
        Some(&self.snapshots)
    }

    fn volumes(&self) -> Option<&dyn VolumeProvider> {
        Some(&self.volumes)
    }
}

/// A Daytona-backed sandbox handle.
pub struct DaytonaSandbox {
    id:           SandboxId,
    name:         Option<String>,
    capabilities: Capabilities,
    client:       DaytonaClient,
    sdk_id:       String,
    working_dir:  String,
    nested:       Option<NestedDocker>,
    exec:         DaytonaExec,
    git:          DaytonaGit,
    fs:           DaytonaFs,
    access:       DaytonaAccess,
    logs:         DaytonaLogs,
    pty:          DaytonaPty,
    events:       EventEmitter,
}

impl DaytonaSandbox {
    fn container(&self) -> Option<&NestedDocker> {
        self.nested
            .as_ref()
            .filter(|nested| nested.targets_container())
    }

    /// The nested Docker client holds a preview token scoped to one
    /// running VM generation, so every verb that ends that generation
    /// clears it here. Keeping the contract in one place is why `pause`
    /// and `archive` cannot forget it.
    async fn vm_generation_ended(&self) {
        if let Some(nested) = &self.nested {
            nested.stopped().await;
        }
    }

    async fn start_with_docker(&self) -> Result<()> {
        self.start_inner().await?;
        self.vm_generation_ended().await;
        if let Some(nested) = &self.nested {
            nested.sandbox().await?;
        }
        Ok(())
    }

    async fn sdk(&self) -> Result<daytona_sdk::Sandbox> {
        self.client
            .get(&self.sdk_id)
            .await
            .map_err(|error| daytona_error("fetching sandbox", error))
    }

    /// Polls until the sandbox settles in a stable state, bounded by
    /// [`TRANSITION_BUDGET`] from the caller's `started` so waits and
    /// retries share one budget. A sandbox that disappears mid-wait
    /// reports `Deleted`.
    async fn wait_for_stable_state(
        &self,
        operation: &str,
        started: Instant,
    ) -> Result<SandboxState> {
        let mut attempt = 0_u64;
        loop {
            attempt += 1;
            let state = match self.client.get(&self.sdk_id).await {
                Ok(sdk) => map_state(sdk.state),
                Err(error) if is_not_found(&error) => return Ok(SandboxState::Deleted),
                Err(error) => return Err(daytona_error("fetching sandbox", error)),
            };
            tracing::debug!(attempt, state = ?state, "sandbox transition state observed");
            if state.is_stable() {
                return Ok(state);
            }
            let elapsed = started.elapsed();
            if elapsed >= TRANSITION_BUDGET {
                return Err(Error::Timeout {
                    operation: operation.to_owned(),
                    elapsed,
                });
            }
            time::sleep(TRANSITION_POLL).await;
        }
    }

    /// Budget check between lifecycle retries, with one poll interval
    /// of pause so repeated rejections cannot spin.
    async fn transition_retry_pause(&self, operation: &str, started: Instant) -> Result<()> {
        let elapsed = started.elapsed();
        if elapsed >= TRANSITION_BUDGET {
            return Err(Error::Timeout {
                operation: operation.to_owned(),
                elapsed,
            });
        }
        time::sleep(TRANSITION_POLL).await;
        Ok(())
    }

    async fn start_inner(&self) -> Result<()> {
        let started = Instant::now();
        // Start is documented as a no-op on a running sandbox; Daytona
        // rejects a start POST on one, so check first (as fabro did).
        // The check can race another actor — the loop below still
        // handles every non-Running answer.
        let current = self
            .client
            .get(&self.sdk_id)
            .await
            .map_err(|error| daytona_error("fetching sandbox", error))?;
        if map_state(current.state) == SandboxState::Running {
            return Ok(());
        }
        loop {
            match self.client.start(&self.sdk_id).await {
                Ok(_) => return Ok(()),
                // Another actor's transition is in flight: wait it out
                // and retry until the budget runs out.
                Err(error) if is_state_change_in_progress(&error) => {
                    let state = self
                        .wait_for_stable_state("starting sandbox", started)
                        .await?;
                    if state == SandboxState::Running {
                        return Ok(());
                    }
                    self.transition_retry_pause("starting sandbox", started)
                        .await?;
                }
                Err(error) => return Err(daytona_error("starting sandbox", error)),
            }
        }
    }

    async fn stop_inner(&self) -> Result<()> {
        let started = Instant::now();
        loop {
            match self.client.stop(&self.sdk_id).await {
                Ok(_) => return Ok(()),
                // Ephemeral sandboxes destroy themselves on stop.
                Err(error) if is_not_found(&error) => return Ok(()),
                // The in-flight transition may be the stop itself (an
                // auto-stop that fired first).
                Err(error) if is_state_change_in_progress(&error) => {
                    match self
                        .wait_for_stable_state("stopping sandbox", started)
                        .await?
                    {
                        SandboxState::Stopped | SandboxState::Archived | SandboxState::Deleted => {
                            return Ok(());
                        }
                        _ => {
                            self.transition_retry_pause("stopping sandbox", started)
                                .await?;
                        }
                    }
                }
                Err(error) => return Err(daytona_error("stopping sandbox", error)),
            }
        }
    }

    /// One bounded delete call: a stalled REST call cannot block a
    /// cleanup path indefinitely.
    async fn delete_once(&self) -> Result<StdResult<(), DaytonaError>> {
        match time::timeout(CLEANUP_TIMEOUT, self.client.delete(&self.sdk_id)).await {
            Ok(result) => Ok(result),
            Err(_) => Err(Error::Timeout {
                operation: "deleting sandbox".to_owned(),
                elapsed:   CLEANUP_TIMEOUT,
            }),
        }
    }

    async fn delete_inner(&self) -> Result<()> {
        let started = Instant::now();
        loop {
            match self.delete_once().await? {
                Ok(()) => return Ok(()),
                Err(error) if is_not_found(&error) => return Ok(()),
                Err(error) if is_state_change_in_progress(&error) => {
                    // A delete racing an in-flight destroy is already
                    // satisfied: the accepted delete also returns while
                    // destruction still runs, so a rejected repeat must
                    // not wait out a slow destroy (observed >2 minutes
                    // live) for the same outcome.
                    let state = match self.client.get(&self.sdk_id).await {
                        Ok(sdk) => map_state(sdk.state),
                        Err(error) if is_not_found(&error) => return Ok(()),
                        Err(error) => return Err(daytona_error("fetching sandbox", error)),
                    };
                    if matches!(state, SandboxState::Deleting | SandboxState::Deleted) {
                        return Ok(());
                    }
                    match self
                        .wait_for_stable_state("deleting sandbox", started)
                        .await?
                    {
                        SandboxState::Deleted => return Ok(()),
                        _ => {
                            self.transition_retry_pause("deleting sandbox", started)
                                .await?;
                        }
                    }
                }
                Err(error) => return Err(daytona_error("deleting sandbox", error)),
            }
        }
    }
}

#[async_trait]
impl Sandbox for DaytonaSandbox {
    fn id(&self) -> &SandboxId {
        &self.id
    }

    fn capabilities(&self) -> &Capabilities {
        &self.capabilities
    }

    #[tracing::instrument(skip_all, fields(provider_kind = "daytona", sandbox_id = %self.id), err)]
    async fn describe(&self) -> Result<SandboxStatus> {
        match self.client.get(&self.sdk_id).await {
            Ok(sdk) => status_from_sdk(&self.client, &sdk),
            Err(error) if is_not_found(&error) => {
                let mut status = SandboxStatus::new(self.id.clone(), SandboxState::Deleted);
                status.name.clone_from(&self.name);
                Ok(status)
            }
            Err(error) => Err(daytona_error("fetching sandbox", error)),
        }
    }

    fn working_directory(&self) -> &str {
        &self.working_dir
    }

    fn runtime_directory(&self) -> Option<&str> {
        Some(RUNTIME_DIRECTORY)
    }

    async fn environment(&self) -> Result<BTreeMap<String, String>> {
        if let Some(container) = self.container() {
            return container.sandbox().await?.environment().await;
        }
        let result = self.exec.run(&ExecSpec::new("env").arg("-0")).await?;
        if !result.success() {
            return Err(Error::Exec(
                ExecFailure::new(
                    "reading VM environment",
                    result.termination,
                    result.exit_code,
                    result.stdout,
                    result.stderr,
                )
                .with_duration(result.duration),
            ));
        }
        let output = String::from_utf8(result.stdout)
            .map_err(|error| docker_transport::transport_error("decoding VM environment", error))?;
        output
            .split_terminator('\0')
            .map(|entry| {
                let (key, value) = entry.split_once('=').ok_or_else(|| {
                    Error::invalid_spec("environment", "expected KEY=VALUE entries")
                })?;
                Ok((key.to_owned(), value.to_owned()))
            })
            .collect()
    }

    #[tracing::instrument(skip_all, fields(provider_kind = "daytona", sandbox_id = %self.id), err)]
    async fn platform_info(&self) -> Result<PlatformInfo> {
        if let Some(container) = self.container() {
            return container.sandbox().await?.platform_info().await;
        }
        // uname prints its fields in canonical order — sysname, release,
        // machine — regardless of flag order.
        let result = self
            .exec
            .run(
                &ExecSpec::new("uname")
                    .args(["-s", "-r", "-m"])
                    .timeout(Duration::from_secs(60)),
            )
            .await?;
        let text = result.stdout_lossy();
        let mut parts = text.split_whitespace();
        let os = parts.next().unwrap_or("linux").to_lowercase();
        let version = parts.next().unwrap_or("").to_owned();
        let arch = parts.next().unwrap_or("").to_owned();
        Ok(PlatformInfo::new(os, arch, version))
    }

    #[tracing::instrument(skip_all, fields(provider_kind = "daytona", sandbox_id = %self.id), err)]
    async fn start(&self) -> Result<()> {
        self.events
            .run(
                EventSubject::sandbox(Some(self.id.clone())),
                Action::Start,
                |_| self.start_with_docker(),
            )
            .await
    }

    #[tracing::instrument(skip_all, fields(provider_kind = "daytona", sandbox_id = %self.id), err)]
    async fn stop(&self) -> Result<()> {
        self.events
            .run(
                EventSubject::sandbox(Some(self.id.clone())),
                Action::Stop,
                |_| async {
                    self.stop_inner().await?;
                    self.vm_generation_ended().await;
                    Ok(())
                },
            )
            .await
    }

    #[tracing::instrument(skip_all, fields(provider_kind = "daytona", sandbox_id = %self.id), err)]
    async fn delete(&self) -> Result<()> {
        self.events
            .run(
                EventSubject::sandbox(Some(self.id.clone())),
                Action::Delete,
                |_| async {
                    self.delete_inner().await?;
                    self.vm_generation_ended().await;
                    Ok(())
                },
            )
            .await
    }

    #[tracing::instrument(skip_all, fields(provider_kind = "daytona", sandbox_id = %self.id), err)]
    async fn archive(&self) -> Result<()> {
        if !self.capabilities.lifecycle.archive {
            return Err(Error::unsupported(Capability::LifecycleArchive));
        }
        self.events
            .run(
                EventSubject::sandbox(Some(self.id.clone())),
                Action::Archive,
                |_| async {
                    let mut sdk = self.sdk().await?;
                    sdk.archive()
                        .await
                        .map_err(|error| daytona_error("archiving sandbox", error))?;
                    self.vm_generation_ended().await;
                    Ok(())
                },
            )
            .await
    }

    #[tracing::instrument(skip_all, fields(provider_kind = "daytona", sandbox_id = %self.id), err)]
    async fn pause(&self) -> Result<()> {
        if !self.capabilities.lifecycle.pause {
            return Err(Error::unsupported(Capability::LifecyclePause));
        }
        // The SDK applies the upstream contract: the pause completes when
        // the sandbox has left the pausing state, not only on exactly
        // Paused. VM classes only; the per-sandbox capability set masks
        // it elsewhere and the server enforces it regardless.
        self.events
            .run(
                EventSubject::sandbox(Some(self.id.clone())),
                Action::Pause,
                |_| async {
                    let mut sdk = self.sdk().await?;
                    sdk.pause_with_timeout(TRANSITION_BUDGET)
                        .await
                        .map_err(|error| daytona_error("pausing sandbox", error))?;
                    self.vm_generation_ended().await;
                    Ok(())
                },
            )
            .await
    }

    #[tracing::instrument(skip_all, fields(provider_kind = "daytona", sandbox_id = %self.id), err)]
    async fn resume(&self) -> Result<()> {
        if !self.capabilities.lifecycle.pause {
            return Err(Error::unsupported(Capability::LifecyclePause));
        }
        // Daytona has no separate resume endpoint: start resumes a
        // paused sandbox.
        self.events
            .run(
                EventSubject::sandbox(Some(self.id.clone())),
                Action::Resume,
                |_| self.start_with_docker(),
            )
            .await
    }

    #[tracing::instrument(skip_all, fields(provider_kind = "daytona", sandbox_id = %self.id), err)]
    async fn fork(&self, options: &ForkOptions) -> Result<Arc<dyn Sandbox>> {
        if !self.capabilities.lifecycle.fork {
            return Err(Error::unsupported(Capability::LifecycleFork));
        }
        self.events
            .run(
                EventSubject::sandbox(Some(self.id.clone())),
                Action::Fork,
                |_| async {
                    let sdk = self.sdk().await?;
                    let current = map_state(sdk.state);
                    if current != SandboxState::Running {
                        return Err(Error::InvalidState {
                            current,
                            action: Action::Fork,
                        });
                    }
                    let forked = sdk
                        .fork_with_timeout(options.name.as_deref(), CREATE_TIMEOUT)
                        .await
                        .map_err(|error| daytona_error("forking sandbox", error))?;
                    let child_state = map_state(forked.state);
                    if child_state != SandboxState::Running {
                        return Err(Error::InvalidState {
                            current: child_state,
                            action:  Action::Fork,
                        });
                    }
                    // The child shares the parent's class, so the parent's (already
                    // narrowed) capability set is the right base.
                    Ok(build_handle(
                        &self.client,
                        &self.capabilities,
                        forked,
                        self.events.clone(),
                    )
                    .await? as Arc<dyn Sandbox>)
                },
            )
            .await
    }

    #[tracing::instrument(skip_all, fields(provider_kind = "daytona", sandbox_id = %self.id), err)]
    async fn snapshot(&self, options: &SandboxSnapshotOptions) -> Result<SnapshotId> {
        if !self.capabilities.lifecycle.snapshot_sandbox {
            return Err(Error::unsupported(Capability::LifecycleSnapshotSandbox));
        }
        let snapshot_caps = self
            .capabilities
            .snapshots
            .as_ref()
            .ok_or_else(|| Error::unsupported(Capability::Snapshots))?;
        let mode_capability = match options.mode {
            SnapshotMode::Filesystem if snapshot_caps.filesystem_from_sandbox => None,
            SnapshotMode::Filesystem => Some(Capability::SnapshotsFilesystem),
            SnapshotMode::LiveProcessState if snapshot_caps.live_process_state_from_sandbox => None,
            SnapshotMode::LiveProcessState => Some(Capability::SnapshotsLiveProcessState),
            _ => {
                return Err(Error::invalid_spec(
                    "mode",
                    "unsupported sandbox snapshot mode",
                ));
            }
        };
        if let Some(capability) = mode_capability {
            return Err(Error::unsupported(capability));
        }
        let name = options.name.clone().unwrap_or_else(generated_snapshot_name);
        self.events
            .run(
                EventSubject::sandbox(Some(self.id.clone())),
                Action::Snapshot,
                |_| async {
                    create_sandbox_snapshot(&self.client, &self.sdk_id, &name, options.mode).await
                },
            )
            .await
    }

    #[tracing::instrument(skip_all, fields(provider_kind = "daytona", sandbox_id = %self.id), err)]
    async fn update_network(&self, policy: &NetworkPolicy) -> Result<()> {
        // Runtime updates bypass spec validation, so the allow-list
        // emptiness invariant is re-checked at this boundary.
        policy.validate()?;
        let mut settings = UpdateSandboxNetworkSettings::new();
        match policy {
            NetworkPolicy::AllowAll => settings.network_block_all = Some(false),
            NetworkPolicy::Block => settings.network_block_all = Some(true),
            NetworkPolicy::CidrAllowList { cidrs } => {
                settings.network_allow_list = Some(cidrs.join(","));
            }
            NetworkPolicy::DomainAllowList { domains } => {
                settings.domain_allow_list = Some(domains.join(","));
            }
            NetworkPolicy::ProviderDefault => {
                return Err(Error::invalid_spec(
                    "network",
                    "provider_default names no concrete policy to apply at runtime",
                ));
            }
            _ => return Err(Error::invalid_spec("network", "unsupported network policy")),
        }
        self.events
            .run(
                EventSubject::sandbox(Some(self.id.clone())),
                Action::UpdateNetwork,
                |_| async {
                    let mut sdk = self.sdk().await?;
                    sdk.update_network_settings(settings)
                        .await
                        .map_err(|error| daytona_error("updating network settings", error))
                },
            )
            .await
    }

    #[tracing::instrument(skip_all, fields(provider_kind = "daytona", sandbox_id = %self.id), err)]
    async fn refresh_activity(&self) -> Result<()> {
        // A trivial exec is genuine activity and resets the idle timers.
        // (The pinned SDK's update_last_activity now sends a valid body;
        // the exec keeps this path independent of that endpoint.)
        self.events
            .run(
                EventSubject::sandbox(Some(self.id.clone())),
                Action::RefreshActivity,
                |_| async {
                    let spec = ExecSpec::new("true").timeout(Duration::from_secs(30));
                    let result = self.exec.run(&spec).await?;
                    if result.success() {
                        Ok(())
                    } else {
                        Err(Error::invalid_spec(
                            "refresh_activity",
                            "keepalive command failed",
                        ))
                    }
                },
            )
            .await
    }

    #[tracing::instrument(skip_all, fields(provider_kind = "daytona", sandbox_id = %self.id), err)]
    async fn resize(&self, resources: &Resources) -> Result<()> {
        let _ = resources;
        Err(Error::unsupported(Capability::LifecycleResize))
    }

    #[tracing::instrument(skip_all, fields(provider_kind = "daytona", sandbox_id = %self.id), err)]
    async fn set_timers(&self, timers: &LifecycleTimers) -> Result<()> {
        let auto_stop = timers.auto_stop_after_idle.map(minutes);
        let auto_pause = timers.auto_pause_after_idle.map(minutes);
        if auto_stop.is_some_and(|interval| interval != 0)
            && auto_pause.is_some_and(|interval| interval != 0)
        {
            return Err(Error::invalid_spec(
                "timers",
                "auto_stop and auto_pause are mutually exclusive; \
                 set at most one to a non-zero value",
            ));
        }
        self.events
            .run(
                EventSubject::sandbox(Some(self.id.clone())),
                Action::SetTimers,
                |_| async {
                    let mut sdk = self.sdk().await?;
                    // Enabling auto-pause requires auto-stop be disabled first (the
                    // server allows at most one non-zero); when the caller enables
                    // auto-pause without saying anything about auto-stop, disable it
                    // for them — the documented upstream sequence.
                    if auto_pause.is_some_and(|interval| interval != 0) && auto_stop.is_none() {
                        sdk.set_autostop_interval(0)
                            .await
                            .map_err(|error| daytona_error("disabling auto-stop", error))?;
                    }
                    if let Some(idle) = auto_stop {
                        sdk.set_autostop_interval(idle)
                            .await
                            .map_err(|error| daytona_error("setting auto-stop", error))?;
                    }
                    if let Some(pause) = auto_pause {
                        sdk.set_auto_pause_interval(pause)
                            .await
                            .map_err(|error| daytona_error("setting auto-pause", error))?;
                    }
                    if let Some(archive) = timers.auto_archive_after_stop {
                        sdk.set_auto_archive_interval(minutes(archive))
                            .await
                            .map_err(|error| daytona_error("setting auto-archive", error))?;
                    }
                    if let Some(delete) = timers.auto_delete_after_stop {
                        sdk.set_auto_delete_interval(auto_delete_minutes(delete))
                            .await
                            .map_err(|error| daytona_error("setting auto-delete", error))?;
                    }
                    if let Some(ttl) = timers.ttl {
                        // The deadline re-anchors from now; zero disables (subject to
                        // the org/region maximum lifespan).
                        sdk.set_ttl(minutes(ttl))
                            .await
                            .map_err(|error| daytona_error("setting ttl", error))?;
                    }
                    Ok(())
                },
            )
            .await
    }

    #[tracing::instrument(
        skip_all,
        fields(
            provider_kind = "daytona",
            sandbox_id = %self.id,
            label_count = labels.len()
        ),
        err
    )]
    async fn set_labels(&self, labels: &BTreeMap<String, String>) -> Result<()> {
        let all = stored_labels(
            labels,
            Some(&self.working_dir),
            self.nested.as_ref().map(NestedDocker::target),
        );
        self.events
            .run(
                EventSubject::sandbox(Some(self.id.clone())),
                Action::SetLabels,
                |_| async {
                    let mut sdk = self.sdk().await?;
                    sdk.set_labels(all)
                        .await
                        .map(|_| ())
                        .map_err(|error| daytona_error("setting labels", error))
                },
            )
            .await
    }

    fn exec(&self) -> &dyn Exec {
        self.container()
            .map_or(&self.exec as &dyn Exec, |nested| nested)
    }

    fn fs(&self) -> &dyn Filesystem {
        self.container()
            .map_or(&self.fs as &dyn Filesystem, |nested| nested)
    }

    fn provider_git(&self) -> Option<&dyn Git> {
        self.container().is_none().then_some(&self.git)
    }

    fn one_shot(&self) -> Option<&dyn OneShot> {
        self.nested.as_ref().map(|nested| nested as &dyn OneShot)
    }

    fn preview_urls(&self) -> Option<&dyn PreviewUrls> {
        self.capabilities
            .access
            .preview_urls
            .then_some(&self.access)
    }

    fn ssh(&self) -> Option<&dyn SshAccess> {
        self.capabilities.access.ssh.then_some(&self.access)
    }

    fn pty(&self) -> Option<&dyn Pty> {
        Some(
            self.container()
                .map_or(&self.pty as &dyn Pty, |nested| nested),
        )
    }

    fn logs(&self) -> Option<&dyn Logs> {
        self.capabilities
            .logs
            .as_ref()
            .map(|_| &self.logs as &dyn Logs)
    }

    fn web_terminal(&self) -> Option<&dyn WebTerminal> {
        self.capabilities
            .access
            .web_terminal
            .then_some(&self.access)
    }

    fn vnc(&self) -> Option<&dyn Vnc> {
        self.capabilities.access.vnc.then_some(&self.access)
    }
}

fn map_snapshot_state(state: ApiSnapshotState) -> SnapshotState {
    use ApiSnapshotState as Ds;
    match state {
        Ds::Building | Ds::Pending | Ds::Pulling | Ds::Snapshotting => SnapshotState::Building,
        Ds::Active => SnapshotState::Active,
        Ds::Inactive => SnapshotState::Inactive,
        Ds::Error | Ds::BuildFailed => SnapshotState::Error,
        Ds::Removing => SnapshotState::Deleting,
        Ds::UnknownDefaultOpenApi => SnapshotState::Unknown,
    }
}

fn snapshot_status(dto: SnapshotDto) -> Result<SnapshotStatus> {
    let id = SnapshotId::try_new(dto.id)
        .map_err(|error| Error::invalid_spec("snapshot_id", error.to_string()))?;
    let mut resources = Resources::default();
    resources.cpu_cores = to_u64(dto.cpu)
        .and_then(|cpu| u32::try_from(cpu).ok())
        .filter(|cpu| *cpu > 0);
    resources.memory_mb = to_u64(dto.mem * 1024.0).filter(|mb| *mb > 0);
    resources.disk_mb = to_u64(dto.disk * 1024.0).filter(|mb| *mb > 0);
    resources.gpus = to_u64(dto.gpu)
        .and_then(|gpu| u32::try_from(gpu).ok())
        .filter(|gpu| *gpu > 0);

    let mut status = SnapshotStatus::new(id, map_snapshot_state(dto.state));
    status.name = Some(dto.name);
    status.sandbox_kind = dto.sandbox_class.map(sandbox_kind_from_snapshot_class);
    status.regions = dto.region_ids.unwrap_or_default();
    status.resources = (resources != Resources::default()).then_some(resources);
    status.error_reason = dto.error_reason;
    status.size_bytes = dto.size.and_then(to_u64);
    Ok(status)
}

struct DaytonaSnapshots {
    client: DaytonaClient,
    kind:   ProviderKind,
}

#[async_trait]
impl SnapshotProvider for DaytonaSnapshots {
    #[tracing::instrument(skip_all, fields(provider_kind = "daytona"), err)]
    async fn create(
        &self,
        spec: &SnapshotSpec,
        events: Option<EventContext>,
    ) -> Result<SnapshotId> {
        spec.validate()?;
        let name = spec.name.clone().unwrap_or_else(generated_snapshot_name);
        let emitter = EventEmitter::new(self.kind.clone(), events);
        emitter
            .run(
                EventSubject::pending_snapshot(Some(name.clone())),
                Action::Create,
                |reporter| async move {
                    reporter
                        .progress(sandbox_driver::Progress::new(
                            sandbox_driver::ProgressCode::SNAPSHOT_BUILD,
                        ))
                        .await;
                    let (image, sandbox_class) = match &spec.source {
            SnapshotSource::Image { reference } => (
                ImageSource::Name(reference.clone()),
                daytona_snapshot_class(spec.sandbox_kind.unwrap_or(SandboxKind::Container))?,
            ),
            SnapshotSource::Dockerfile { content } => {
                if spec.sandbox_kind == Some(SandboxKind::VirtualMachine) {
                    return Err(Error::unsupported(Capability::SnapshotsVmFromDockerfile));
                }
                (
                    ImageSource::Custom(DockerImage::from_dockerfile(content)),
                    DaytonaCreateSandboxClass::CONTAINER,
                )
            }
            SnapshotSource::Sandbox { id, mode } => {
                let sdk = self
                    .client
                    .get(id.as_str())
                    .await
                    .map_err(|error| daytona_error("fetching sandbox for snapshot", error))?;
                let actual_kind = sdk.sandbox_class.map(sandbox_kind_from_sandbox_class);
                if let Some(requested) = spec.sandbox_kind {
                    if actual_kind != Some(requested) {
                        return Err(Error::invalid_spec(
                            "sandbox_kind",
                            format!(
                                "the source sandbox has kind {actual_kind:?}, not {requested:?}"
                            ),
                        ));
                    }
                }
                if let Some(region) = &spec.region {
                    if sdk.target != *region {
                        return Err(Error::invalid_spec(
                            "region",
                            format!(
                                "the source sandbox is in region {}, not {region}",
                                sdk.target
                            ),
                        ));
                    }
                }
                if spec.resources != Resources::default() {
                    return Err(Error::invalid_spec(
                        "resources",
                        "resources are inherited when snapshotting a sandbox",
                    ));
                }
                if *mode == SnapshotMode::LiveProcessState
                    && matches!(
                        sdk.sandbox_class,
                        Some(DaytonaSandboxClass::CONTAINER | DaytonaSandboxClass::ANDROID)
                    )
                {
                    return Err(Error::unsupported(Capability::SnapshotsLiveProcessState));
                }
                create_sandbox_snapshot(&self.client, id.as_str(), &name, *mode).await?;
                let created = created_snapshot_id(&self.client, &name).await?;
                reporter.set_subject(EventSubject::snapshot(Some(created.clone())));
                return Ok(created);
            }
            _ => return Err(Error::invalid_spec("source", "unsupported snapshot source")),
        };
                    let params = CreateSnapshotParams {
                        name,
                        image,
                        region_id: spec.region.clone(),
                        sandbox_class: Some(sandbox_class),
                        resources: sdk_resources(&spec.resources),
                        entrypoint: None,
                    };
                    let created = self
                        .client
                        .snapshot
                        .create(&params)
                        .await
                        .map_err(|error| daytona_error("creating snapshot", error))?;
                    let id = SnapshotId::try_new(created.id)
                        .map_err(|error| Error::invalid_spec("snapshot_id", error.to_string()))?;
                    reporter.set_subject(EventSubject::snapshot(Some(id.clone())));
                    Ok(id)
                },
            )
            .await
    }

    #[tracing::instrument(
        skip_all,
        fields(provider_kind = "daytona", snapshot_id = %id),
        err
    )]
    async fn get(&self, id: &SnapshotId) -> Result<SnapshotStatus> {
        let dto = self
            .client
            .snapshot
            .get(id.as_str())
            .await
            .map_err(|error| {
                if is_not_found(&error) {
                    Error::NotFound {
                        resource: ResourceKind::Snapshot,
                        id:       id.as_str().to_owned(),
                    }
                } else {
                    daytona_error("fetching snapshot", error)
                }
            })?;
        snapshot_status(dto)
    }

    #[tracing::instrument(skip_all, fields(provider_kind = "daytona"), err)]
    async fn list(&self, filter: &SnapshotFilter) -> Result<Vec<SnapshotStatus>> {
        let mut statuses = Vec::new();
        let mut page_number: i32 = 1;
        loop {
            let page = self
                .client
                .snapshot
                .list(Some(page_number), Some(LIST_PAGE_SIZE))
                .await
                .map_err(|error| daytona_error("listing snapshots", error))?;
            tracing::debug!(
                page_number,
                item_count = page.items.len(),
                "snapshot page received"
            );
            for dto in page.items {
                if let Some(name) = &filter.name {
                    if dto.name != *name {
                        continue;
                    }
                }
                statuses.push(snapshot_status(dto)?);
            }
            if page.total_pages <= f64::from(page_number) {
                break;
            }
            page_number += 1;
        }
        Ok(statuses)
    }

    #[tracing::instrument(
        skip_all,
        fields(provider_kind = "daytona", snapshot_id = %id),
        err
    )]
    async fn delete(&self, id: &SnapshotId, events: Option<EventContext>) -> Result<()> {
        EventEmitter::new(self.kind.clone(), events)
            .run(
                EventSubject::snapshot(Some(id.clone())),
                Action::Delete,
                |_| async {
                    match self.client.snapshot.delete(id.as_str()).await {
                        Ok(()) => Ok(()),
                        Err(error) if is_not_found(&error) => Ok(()),
                        Err(error) => {
                            // Same asynchronous-deletion idempotency as volumes.
                            if let Ok(dto) = self.client.snapshot.get(id.as_str()).await {
                                if map_snapshot_state(dto.state) == SnapshotState::Deleting {
                                    return Ok(());
                                }
                            }
                            Err(daytona_error("deleting snapshot", error))
                        }
                    }
                },
            )
            .await
    }

    #[tracing::instrument(
        skip_all,
        fields(provider_kind = "daytona", snapshot_id = %id, follow),
        err
    )]
    async fn build_logs(&self, id: &SnapshotId, follow: bool, sink: LogSink) -> Result<()> {
        let sink_error = Arc::new(Mutex::new(None));
        let callback_error = Arc::clone(&sink_error);
        let outcome = self
            .client
            .snapshot
            .stream_build_logs(id.as_str(), follow, move |chunk| {
                let sink = Arc::clone(&sink);
                let callback_error = Arc::clone(&callback_error);
                async move {
                    if let Err(error) = sink(chunk).await {
                        *callback_error.lock().expect("sink error lock") = Some(error);
                        return Err(DaytonaError::general("sandbox-driver log sink failed"));
                    }
                    Ok(())
                }
            })
            .await;
        if let Some(error) = sink_error.lock().expect("sink error lock").take() {
            return Err(error);
        }
        outcome.map_err(|error| daytona_error("following snapshot build logs", error))
    }

    #[tracing::instrument(
        skip_all,
        fields(provider_kind = "daytona", snapshot_id = %id),
        err
    )]
    async fn activate(&self, id: &SnapshotId, events: Option<EventContext>) -> Result<()> {
        EventEmitter::new(self.kind.clone(), events)
            .run(
                EventSubject::snapshot(Some(id.clone())),
                Action::Activate,
                |_| async {
                    // The SDK resolves ids and names against the ID-only endpoint.
                    let started = Instant::now();
                    let mut attempt = 0_u64;
                    loop {
                        attempt += 1;
                        tracing::debug!(attempt, "snapshot activation requested");
                        match self.client.snapshot.activate(id.as_str()).await {
                            Ok(_) => return Ok(()),
                            Err(error) if is_not_found(&error) => {
                                return Err(Error::NotFound {
                                    resource: ResourceKind::Snapshot,
                                    id:       id.as_str().to_owned(),
                                });
                            }
                            Err(error) if is_snapshot_deactivation_in_progress(&error) => {
                                let elapsed = started.elapsed();
                                if elapsed >= SNAPSHOT_ACTIVATE_BUDGET {
                                    return Err(Error::Timeout {
                                        operation: "waiting to activate snapshot".to_owned(),
                                        elapsed,
                                    });
                                }
                                time::sleep(SNAPSHOT_ACTIVATE_POLL).await;
                            }
                            Err(error) => {
                                return Err(daytona_error("activating snapshot", error));
                            }
                        }
                    }
                },
            )
            .await
    }

    #[tracing::instrument(
        skip_all,
        fields(provider_kind = "daytona", snapshot_id = %id),
        err
    )]
    async fn deactivate(&self, id: &SnapshotId, events: Option<EventContext>) -> Result<()> {
        EventEmitter::new(self.kind.clone(), events)
            .run(
                EventSubject::snapshot(Some(id.clone())),
                Action::Deactivate,
                |_| async {
                    // Deactivation is unwrapped by the reference SDKs (the generated
                    // client has it); the endpoint is ID-only, so resolve a name
                    // through get first, mirroring the SDK's activate resolution.
                    let configuration = self.client.api_configuration();
                    let organization = self.client.organization_id();
                    match snapshots_api::deactivate_snapshot(
                        configuration,
                        id.as_str(),
                        organization,
                    )
                    .await
                    {
                        Ok(()) => return Ok(()),
                        Err(error) if is_generated_not_found(&error) => {}
                        Err(error) => {
                            return Err(generated_error("deactivating snapshot", error));
                        }
                    }
                    let resolved = match self.client.snapshot.get(id.as_str()).await {
                        Ok(dto) => dto.id,
                        Err(error) if is_not_found(&error) => {
                            return Err(Error::NotFound {
                                resource: ResourceKind::Snapshot,
                                id:       id.as_str().to_owned(),
                            });
                        }
                        Err(error) => return Err(daytona_error("fetching snapshot", error)),
                    };
                    snapshots_api::deactivate_snapshot(configuration, &resolved, organization)
                        .await
                        .map_err(|error| generated_error("deactivating snapshot", error))
                },
            )
            .await
    }
}

fn map_volume_state(state: ApiVolumeState) -> VolumeState {
    use ApiVolumeState as Ds;
    match state {
        Ds::Creating | Ds::PendingCreate => VolumeState::Creating,
        Ds::Ready => VolumeState::Ready,
        Ds::Deleting | Ds::PendingDelete => VolumeState::Deleting,
        Ds::Deleted => VolumeState::Deleted,
        Ds::Error => VolumeState::Error,
        Ds::UnknownDefaultOpenApi => VolumeState::Unknown,
    }
}

fn volume_status(dto: VolumeDto) -> Result<VolumeStatus> {
    let id = VolumeId::try_new(dto.id)
        .map_err(|error| Error::invalid_spec("volume_id", error.to_string()))?;
    let mut status = VolumeStatus::new(id, map_volume_state(dto.state));
    status.name = Some(dto.name);
    status.error_reason = dto.error_reason;
    Ok(status)
}

struct DaytonaVolumes {
    client: DaytonaClient,
    kind:   ProviderKind,
}

#[async_trait]
impl VolumeProvider for DaytonaVolumes {
    #[tracing::instrument(skip_all, fields(provider_kind = "daytona"), err)]
    async fn create(&self, spec: &VolumeSpec, events: Option<EventContext>) -> Result<VolumeId> {
        EventEmitter::new(self.kind.clone(), events)
            .run(
                EventSubject::pending_volume(Some(spec.name.clone())),
                Action::Create,
                |reporter| async move {
                    // Daytona volumes are elastic; a requested size is ignored.
                    let dto = self
                        .client
                        .volume
                        .create(&spec.name)
                        .await
                        .map_err(|error| daytona_error("creating volume", error))?;
                    let id = VolumeId::try_new(dto.id)
                        .map_err(|error| Error::invalid_spec("volume_id", error.to_string()))?;
                    reporter.set_subject(EventSubject::volume(Some(id.clone())));
                    Ok(id)
                },
            )
            .await
    }

    #[tracing::instrument(
        skip_all,
        fields(provider_kind = "daytona", volume_id = %id),
        err
    )]
    async fn get(&self, id: &VolumeId) -> Result<VolumeStatus> {
        let dto = self.client.volume.get(id.as_str()).await.map_err(|error| {
            if is_not_found(&error) {
                Error::NotFound {
                    resource: ResourceKind::Volume,
                    id:       id.as_str().to_owned(),
                }
            } else {
                daytona_error("fetching volume", error)
            }
        })?;
        volume_status(dto)
    }

    #[tracing::instrument(skip_all, fields(provider_kind = "daytona"), err)]
    async fn list(&self) -> Result<Vec<VolumeStatus>> {
        let volumes = self
            .client
            .volume
            .list()
            .await
            .map_err(|error| daytona_error("listing volumes", error))?;
        volumes.into_iter().map(volume_status).collect()
    }

    #[tracing::instrument(
        skip_all,
        fields(provider_kind = "daytona", volume_id = %id),
        err
    )]
    async fn delete(&self, id: &VolumeId, events: Option<EventContext>) -> Result<()> {
        EventEmitter::new(self.kind.clone(), events)
            .run(
                EventSubject::volume(Some(id.clone())),
                Action::Delete,
                |_| async {
                    match self.client.volume.delete(id.as_str()).await {
                        Ok(()) => Ok(()),
                        Err(error) if is_not_found(&error) => Ok(()),
                        Err(error) => {
                            // Deletion is asynchronous: a repeat delete while the
                            // first is processing is rejected. Idempotency means
                            // checking whether deletion is already underway.
                            if let Ok(dto) = self.client.volume.get(id.as_str()).await {
                                if matches!(
                                    map_volume_state(dto.state),
                                    VolumeState::Deleting | VolumeState::Deleted
                                ) {
                                    return Ok(());
                                }
                            }
                            Err(daytona_error("deleting volume", error))
                        }
                    }
                },
            )
            .await
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap as StdHashMap;
    use std::error::Error as _;

    use super::*;

    #[test]
    fn current_key_identity_uses_its_organization_and_ignores_credentials() {
        let first: CurrentApiKey = serde_json::from_value(serde_json::json!({
            "name": "original", "value": "masked-original", "userId": "user-a",
            "organizationId": "organization-a", "permissions": []
        }))
        .expect("current key");
        let rotated: CurrentApiKey = serde_json::from_value(serde_json::json!({
            "name": "rotated", "value": "masked-rotated", "userId": "user-b",
            "organizationId": "organization-a", "permissions": []
        }))
        .expect("rotated key in the same organization");
        let changed: CurrentApiKey = serde_json::from_value(serde_json::json!({
            "name": "other", "organizationId": "organization-b", "permissions": []
        }))
        .expect("key in another organization");
        assert_eq!(first.organization_id, rotated.organization_id);
        assert_ne!(first.organization_id, changed.organization_id);
    }

    fn api_error(status_code: u16, message: &str) -> DaytonaError {
        DaytonaError::Api {
            status_code,
            message: message.to_owned(),
            headers: StdHashMap::new(),
        }
    }

    #[test]
    fn state_change_in_progress_matches_the_observed_rejection() {
        // Real Daytona traffic reports this class as HTTP 400.
        assert!(is_state_change_in_progress(&api_error(
            400,
            "Sandbox state change in progress"
        )));
        assert!(is_state_change_in_progress(&api_error(
            409,
            "State change in progress"
        )));
        assert!(!is_state_change_in_progress(&api_error(400, "Bad request")));
        assert!(!is_state_change_in_progress(&api_error(
            409,
            "Name conflict"
        )));
    }

    #[test]
    fn snapshot_deactivation_race_matches_the_observed_rejection() {
        assert!(is_snapshot_deactivation_in_progress(&api_error(
            400,
            "Snapshot deactivation is still in progress. Please try again in a few minutes."
        )));
        assert!(!is_snapshot_deactivation_in_progress(&api_error(
            400,
            "Bad request"
        )));
    }

    #[test]
    fn provider_mapping_preserves_sources_and_retry_metadata() {
        let error = daytona_error("listing sandboxes", api_error(503, "service unavailable"));
        let Error::Provider(provider) = error else {
            panic!("expected a provider error");
        };
        assert_eq!(provider.message, "listing sandboxes");
        assert_eq!(provider.code.as_deref(), Some("503"));
        assert!(provider.retryable);
        assert_eq!(
            provider.source().expect("provider source").to_string(),
            "service unavailable"
        );
    }

    #[test]
    fn a_request_timeout_is_not_marked_retryable() {
        // A timeout does not prove the remote operation stopped; a
        // consumer honoring `retryable` must not overlap a still-running
        // first attempt (a clone still writing its target, say).
        let error = daytona_error("cloning git repository", DaytonaError::Timeout {
            message: "request timed out".to_owned(),
        });
        let Error::Provider(provider) = error else {
            panic!("expected a provider error");
        };
        assert_eq!(provider.code.as_deref(), Some("timeout"));
        assert!(!provider.retryable);
    }

    #[test]
    fn authentication_mapping_keeps_the_sdk_cause() {
        let error = daytona_error("connecting to daytona", api_error(401, "invalid token"));
        let Error::Auth(auth) = error else {
            panic!("expected an authentication error");
        };
        assert_eq!(auth.reason, "connecting to daytona");
        assert_eq!(
            auth.source().expect("authentication source").to_string(),
            "invalid token"
        );
    }

    #[tokio::test]
    async fn explicit_connection_config_reaches_the_sdk_client() {
        let provider = DaytonaProvider::connect_with_config(DaytonaConfig {
            api_key: Some("dtn_vault_resolved".to_owned()),
            organization_id: Some("org-1".to_owned()),
            api_url: Some("https://daytona.example/api".to_owned()),
            ..DaytonaConfig::default()
        })
        .await
        .expect("explicit Daytona configuration should initialize the SDK client");

        let sdk_config = provider.client.api_configuration();
        assert_eq!(
            sdk_config.bearer_access_token.as_deref(),
            Some("dtn_vault_resolved")
        );
        assert_eq!(sdk_config.base_path, "https://daytona.example/api");
        assert_eq!(provider.client.organization_id(), Some("org-1"));
    }

    #[test]
    fn rate_limit_mapping_keeps_retry_after() {
        let mut headers = StdHashMap::new();
        headers.insert("Retry-After".to_owned(), "17".to_owned());
        let error = daytona_error("listing sandboxes", DaytonaError::RateLimit {
            message: "slow down".to_owned(),
            headers,
        });
        assert!(matches!(error, Error::RateLimited {
            retry_after: Some(retry_after),
        } if retry_after == Duration::from_secs(17)));
    }

    #[test]
    fn sandbox_class_narrows_lifecycle_capabilities() {
        let base = daytona_capabilities();

        let container = narrowed_capabilities(&base, Some(DaytonaSandboxClass::CONTAINER));
        assert!(container.lifecycle.archive);
        assert!(!container.lifecycle.pause);
        assert!(!container.lifecycle.fork);

        let linux_vm = narrowed_capabilities(&base, Some(DaytonaSandboxClass::LINUX_VM));
        assert!(!linux_vm.lifecycle.archive);
        assert!(linux_vm.lifecycle.pause);
        assert!(linux_vm.lifecycle.fork);

        let android = narrowed_capabilities(&base, Some(DaytonaSandboxClass::ANDROID));
        assert!(!android.lifecycle.archive);
        assert!(!android.lifecycle.pause);
        assert!(!android.lifecycle.fork);
    }

    #[test]
    fn snapshot_capabilities_distinguish_container_and_vm_builds() {
        let caps = daytona_capabilities();
        let snapshots = caps.snapshots.expect("snapshot capabilities");
        assert!(snapshots.from_image_kinds.container);
        assert!(snapshots.from_image_kinds.virtual_machine);
        assert!(snapshots.from_dockerfile_kinds.container);
        assert!(!snapshots.from_dockerfile_kinds.virtual_machine);
    }

    #[test]
    fn base_params_store_the_requested_working_directory_as_internal_metadata() {
        let spec = SandboxSpec::new(SandboxSource::Image {
            reference: "debian:stable-slim".to_owned(),
        })
        .label(WORKING_DIRECTORY_LABEL, "/caller-cannot-override")
        .working_directory("/workspace/final");

        let base = base_params(&spec).expect("valid base params");
        let labels = base.labels.expect("managed labels");
        assert_eq!(
            labels.get(WORKING_DIRECTORY_LABEL).map(String::as_str),
            Some("/workspace/final")
        );
        assert_eq!(labels.get(MANAGED_LABEL).map(String::as_str), Some("true"));
    }

    #[test]
    fn snapshotting_sandboxes_report_running() {
        // Usable during a snapshot: activation and waits must not stall
        // through it.
        assert_eq!(
            map_state(Some(daytona_sdk::SandboxState::Snapshotting)),
            SandboxState::Running
        );
    }

    #[test]
    fn base_params_blank_bash_env_over_any_caller_value() {
        let spec = SandboxSpec::new(SandboxSource::Image {
            reference: "debian:stable-slim".to_owned(),
        })
        .env_var("BASH_ENV", "/etc/injected.sh")
        .env_var("KEEP", "1");

        let base = base_params(&spec).expect("valid base params");
        let env = base.env_vars.expect("env vars");
        // Sandbox-level blank: the inner bash of a session exec sources
        // $BASH_ENV at startup, before any per-exec strip can run.
        assert_eq!(env.get("BASH_ENV").map(String::as_str), Some(""));
        assert_eq!(env.get("KEEP").map(String::as_str), Some("1"));
    }

    #[test]
    fn nested_docker_keeps_private_preview_and_only_nonsecret_target_metadata() {
        let mut spec = SandboxSpec::new(SandboxSource::Image {
            reference: "runner:dind".to_owned(),
        });
        spec.labels
            .insert(nested_docker::TARGET_LABEL.to_owned(), "spoofed".to_owned());
        let options = sandbox_driver_docker::DockerProviderConfig {
            registry_auth: Some(sandbox_driver_docker::RegistryAuth {
                username: "private-user".to_owned(),
                password: "private-password".to_owned(),
                server:   None,
            }),
            ..Default::default()
        };
        spec.provider_config = DaytonaProviderConfig {
            docker: Some(NestedDockerConfig {
                image: "private-image".to_owned(),
                target: DockerExecutionTarget::Container,
                user: None,
                options,
            }),
            ..Default::default()
        }
        .into_value();
        let base = base_params(&spec).unwrap();
        assert_eq!(base.public, Some(false));
        let labels = base.labels.unwrap();
        assert_eq!(labels[nested_docker::TARGET_LABEL], "container");
        assert!(!format!("{labels:?}").contains("private-"));
        spec.public = Some(true);
        assert!(matches!(base_params(&spec), Err(Error::InvalidSpec { .. })));
    }

    #[test]
    fn nested_docker_rejects_vm_sidecars_and_caller_binds_before_provisioning() {
        let mut spec = SandboxSpec::new(SandboxSource::Image {
            reference: "runner:dind".to_owned(),
        });
        for docker in [
            serde_json::json!({"image":"alpine", "target":"virtual_machine", "options":{"sidecars":[{"name":"db","image":"postgres"}]}}),
            serde_json::json!({"image":"alpine", "options":{"binds":[{"host":"/private","container":"/workspace"}]}}),
            serde_json::json!({"image":"alpine", "options":{"host_network":true}}),
            serde_json::json!({"image":" "}),
            serde_json::json!({"image":"alpine", "typo":true}),
        ] {
            spec.provider_config = serde_json::json!({"docker":docker});
            assert!(matches!(base_params(&spec), Err(Error::InvalidSpec { .. })));
        }
    }

    #[test]
    fn base_params_do_not_accept_internal_metadata_as_a_user_label() {
        let spec = SandboxSpec::new(SandboxSource::Image {
            reference: "debian:stable-slim".to_owned(),
        })
        .label(WORKING_DIRECTORY_LABEL, "/caller-injected");

        let base = base_params(&spec).expect("valid base params");
        let labels = base.labels.expect("managed labels");
        assert!(!labels.contains_key(WORKING_DIRECTORY_LABEL));
    }

    #[test]
    fn snapshot_sandbox_resource_overrides_return_invalid_spec() {
        let mut spec = SandboxSpec::new(SandboxSource::Snapshot {
            id: SnapshotId::try_new("snapshot").expect("valid snapshot id"),
        });
        spec.resources.cpu_cores = Some(2);

        let error = validate_supported_creation_fields(&spec)
            .expect_err("snapshot resources should be inherited");
        assert!(matches!(error, Error::InvalidSpec { field, .. } if field == "resources"));
    }

    #[test]
    fn image_sandbox_resource_overrides_pass_creation_field_validation() {
        let mut spec = SandboxSpec::new(SandboxSource::Image {
            reference: "debian:stable-slim".to_owned(),
        });
        spec.resources.cpu_cores = Some(2);
        spec.resources.memory_mb = Some(4096);
        spec.resources.disk_mb = Some(10 * 1024);
        spec.resources.gpus = Some(1);

        validate_supported_creation_fields(&spec).expect("image resources are supported");
    }

    #[test]
    fn snapshot_status_reports_kind_regions_and_resources() {
        let mut dto = SnapshotDto::new(
            "snap-1".to_owned(),
            true,
            "base".to_owned(),
            ApiSnapshotState::Active,
            Some(512.0),
            None,
            2.0,
            1.0,
            4.0,
            20.0,
            None,
            "2026-01-01".to_owned(),
            "2026-01-01".to_owned(),
            None,
            None,
        );
        dto.sandbox_class = Some(DaytonaSnapshotClass::LINUX_VM);
        dto.region_ids = Some(vec!["eu".to_owned(), "us".to_owned()]);

        let status = snapshot_status(dto).expect("maps snapshot status");
        assert_eq!(status.sandbox_kind, Some(SandboxKind::VirtualMachine));
        assert_eq!(status.regions, ["eu", "us"]);
        let resources = status.resources.expect("snapshot resources");
        assert_eq!(resources.cpu_cores, Some(2));
        assert_eq!(resources.memory_mb, Some(4096));
        assert_eq!(resources.disk_mb, Some(20 * 1024));
        assert_eq!(resources.gpus, Some(1));
        assert_eq!(status.size_bytes, Some(512));
    }

    #[test]
    fn minutes_round_up_to_at_least_one() {
        assert_eq!(minutes(Duration::from_secs(30)), 1);
        assert_eq!(minutes(Duration::from_secs(120)), 2);
        assert_eq!(minutes(Duration::from_secs(150)), 3);
    }

    #[test]
    fn minutes_pass_zero_through_as_disabled() {
        // Wire 0 disables auto-stop and defers auto-archive to the
        // maximum interval.
        assert_eq!(minutes(Duration::ZERO), 0);
    }

    #[test]
    fn auto_delete_zero_crosses_as_negative_disabled() {
        // Wire 0 means "delete immediately upon stopping"; disabled is
        // a negative value. Mapping ZERO to 0 would turn "never
        // auto-delete" into destroying the sandbox on every stop.
        assert_eq!(auto_delete_minutes(Duration::ZERO), -1);
        assert_eq!(auto_delete_minutes(Duration::from_secs(90)), 2);
    }

    #[test]
    fn gigabytes_round_up() {
        assert_eq!(gigabytes(1), 1);
        assert_eq!(gigabytes(1024), 1);
        assert_eq!(gigabytes(1025), 2);
    }
}
