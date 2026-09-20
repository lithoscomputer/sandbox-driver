//! The Daytona sandbox handle and its lifecycle.

use std::collections::BTreeMap;
use std::result::Result as StdResult;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use daytona_api_client::models::UpdateSandboxNetworkSettings;
use daytona_sdk::DaytonaError;
use sandbox_driver::{
    Action, Capabilities, Capability, Error, EventEmitter, EventSubject, Exec, ExecFailure,
    ExecSpec, Filesystem, ForkOptions, Git, LifecycleTimers, Logs, NetworkPolicy, OneShot,
    PlatformInfo, PreviewUrls, Pty, Resources, Result, Sandbox, SandboxId, SandboxSnapshotOptions,
    SandboxState, SandboxStatus, SnapshotId, SnapshotMode, SshAccess, Vnc, WebTerminal,
};
use tokio::time;

use crate::labels::{
    TARGET_LABEL, WORKING_DIRECTORY_LABEL, is_internal_label, parse_target, stored_labels,
};
use crate::nested::NestedDocker;
use crate::provider::narrowed_capabilities;
use crate::sdk::{
    DaytonaClient, auto_delete_minutes, dashboard_url, daytona_error, is_not_found,
    is_state_change_in_progress, map_state, minutes, sandbox_kind_from_sandbox_class, to_u64,
};
use crate::snapshots::{create_sandbox_snapshot, generated_snapshot_name};
use crate::{
    CLEANUP_TIMEOUT, CREATE_TIMEOUT, DaytonaAccess, DaytonaExec, DaytonaFs, DaytonaGit,
    DaytonaLogs, DaytonaPty, FALLBACK_WORKING_DIR, RUNTIME_DIRECTORY, TRANSITION_BUDGET,
    TRANSITION_POLL,
};

pub(crate) fn status_from_sdk(
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
    status.snapshot.clone_from(&sdk.snapshot);
    status.network = Some(network_of(sdk));
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

/// The network policy a Daytona sandbox runs under, read back from its
/// settings: blocked, an allow list of CIDRs, or unrestricted.
fn network_of(sdk: &daytona_sdk::Sandbox) -> NetworkPolicy {
    if sdk.network_block_all {
        return NetworkPolicy::Block;
    }
    let cidrs: Vec<String> = sdk
        .network_allow_list
        .as_deref()
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|cidr| !cidr.is_empty())
        .map(str::to_owned)
        .collect();
    if cidrs.is_empty() {
        NetworkPolicy::AllowAll
    } else {
        NetworkPolicy::CidrAllowList { cidrs }
    }
}

/// A Daytona-backed sandbox handle.
pub struct DaytonaSandbox {
    id:                SandboxId,
    name:              Option<String>,
    capabilities:      Capabilities,
    client:            DaytonaClient,
    sdk_id:            String,
    working_dir:       String,
    pub(crate) nested: Option<NestedDocker>,
    exec:              DaytonaExec,
    git:               DaytonaGit,
    fs:                DaytonaFs,
    access:            DaytonaAccess,
    logs:              DaytonaLogs,
    pty:               DaytonaPty,
    events:            EventEmitter,
}

impl DaytonaSandbox {
    /// Builds a sandbox handle from an SDK sandbox, narrowing the capability
    /// set by sandbox class. Shared by the provider (create/attach/undelete)
    /// and by `fork`, which builds the child's handle from an existing one.
    pub(crate) async fn build(
        client: &DaytonaClient,
        base_capabilities: &Capabilities,
        sdk: daytona_sdk::Sandbox,
        events: EventEmitter,
    ) -> Result<Arc<Self>> {
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
            .get(TARGET_LABEL)
            .map(|label| {
                parse_target(label)
                    .map(|target| NestedDocker::new(client, &sdk.id, &working_dir, target))
            })
            .transpose()?;
        let mut capabilities = narrowed_capabilities(base_capabilities, sdk.sandbox_class);
        capabilities.one_shot = None;
        capabilities.exec.stdin_stream = false;
        if let Some(nested) = &nested {
            nested.capabilities(&mut capabilities);
        }
        Ok(Arc::new(Self {
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
}

impl DaytonaSandbox {
    fn container(&self) -> Option<&NestedDocker> {
        self.nested
            .as_ref()
            .filter(|nested| nested.targets_container())
    }

    /// A new sandbox generation must restart Docker and its services
    /// before nested operations resume.
    async fn vm_generation_ended(&self) {
        if let Some(nested) = &self.nested {
            nested.stopped().await;
        }
    }

    async fn start_with_docker(&self) -> Result<()> {
        self.start_inner().await?;
        self.vm_generation_ended().await;
        if let Some(nested) = self.container() {
            nested.ensure_ready().await?;
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
        let result = self.exec().run(&ExecSpec::new("env").arg("-0")).await?;
        if !result.success() {
            return Err(Error::Exec(
                ExecFailure::new(
                    "reading sandbox environment",
                    result.termination,
                    result.exit_code,
                    result.stdout,
                    result.stderr,
                )
                .with_duration(result.duration),
            ));
        }
        let output = String::from_utf8(result.stdout)
            .map_err(|error| Error::invalid_spec("environment", error.to_string()))?;
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
        // uname prints its fields in canonical order — sysname, release,
        // machine — regardless of flag order.
        let result = self
            .exec()
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
                    Ok(Self::build(
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
