//! The container-backed sandbox handle.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bollard::Docker;
use bollard::container::{
    InspectContainerOptions, RemoveContainerOptions, StartContainerOptions, StopContainerOptions,
};
use sandbox_driver::{
    Action, Capabilities, Error, EventEmitter, EventSubject, Exec, ExecSpec, Filesystem, OneShot,
    PlatformInfo, PreviewUrls, ProviderError, Pty, ResourceKind, Result, Sandbox, SandboxId,
    SandboxKind, SandboxState, SandboxStatus, ShellCommand,
};

use crate::access::DockerShellCommand;
use crate::daemon::{
    docker_error, docker_kind, is_not_found, is_not_modified, tolerate_not_modified,
};
use crate::exec::DockerExec;
use crate::forward::DockerForwards;
use crate::fs::DockerFs;
use crate::inspect::{configured_env, status_from_inspect};
use crate::one_shot::{self, DockerOneShot};
use crate::pty::DockerPty;
use crate::{RUNTIME_DIRECTORY, SIDECAR_NETWORK_LABEL, sidecars};

/// A container-backed sandbox.
pub struct DockerSandbox {
    pub(crate) id:            SandboxId,
    pub(crate) name:          Option<String>,
    pub(crate) capabilities:  Capabilities,
    pub(crate) docker:        Docker,
    pub(crate) working_dir:   String,
    pub(crate) labels:        BTreeMap<String, String>,
    pub(crate) exec:          Arc<DockerExec>,
    pub(crate) fs:            DockerFs,
    pub(crate) pty:           DockerPty,
    pub(crate) shell_command: DockerShellCommand,
    /// One-shot containers over the sandbox's workspace, when the
    /// container's mounts told where that workspace is.
    pub(crate) one_shot:      Option<DockerOneShot>,
    /// Port forwards into the container, closed with it.
    pub(crate) forwards:      DockerForwards,
    /// The sidecar network to sweep on delete, when the sandbox has one.
    pub(crate) network:       Option<String>,
    pub(crate) events:        EventEmitter,
}

#[async_trait]
impl Sandbox for DockerSandbox {
    fn id(&self) -> &SandboxId {
        &self.id
    }

    fn capabilities(&self) -> &Capabilities {
        &self.capabilities
    }

    #[tracing::instrument(skip_all, fields(provider_kind = "docker", sandbox_id = %self.id), err)]
    async fn describe(&self) -> Result<SandboxStatus> {
        match self
            .docker
            .inspect_container(self.id.as_str(), None::<InspectContainerOptions>)
            .await
        {
            Ok(inspect) => {
                let mut status = status_from_inspect(self.id.clone(), &inspect);
                if status.labels.is_empty() {
                    status.labels = self.labels.clone();
                }
                Ok(status)
            }
            Err(error) if is_not_found(&error) => {
                let mut status = SandboxStatus::new(self.id.clone(), SandboxState::Deleted);
                status.name.clone_from(&self.name);
                status.sandbox_kind = Some(SandboxKind::Container);
                Ok(status)
            }
            Err(error) => Err(docker_error("inspecting container", error)),
        }
    }

    fn working_directory(&self) -> &str {
        &self.working_dir
    }

    fn runtime_directory(&self) -> Option<&str> {
        Some(RUNTIME_DIRECTORY)
    }

    #[tracing::instrument(skip_all, fields(provider_kind = "docker", sandbox_id = %self.id), err)]
    async fn environment(&self) -> Result<BTreeMap<String, String>> {
        let inspect = self
            .docker
            .inspect_container(self.id.as_str(), None::<InspectContainerOptions>)
            .await
            .map_err(|error| docker_error("inspecting container", error))?;
        Ok(configured_env(&inspect))
    }

    #[tracing::instrument(skip_all, fields(provider_kind = "docker", sandbox_id = %self.id), err)]
    async fn platform_info(&self) -> Result<PlatformInfo> {
        // uname prints its fields in canonical order — sysname, release,
        // machine — regardless of flag order.
        let result = self
            .exec
            .run(
                &ExecSpec::new("uname")
                    .args(["-s", "-r", "-m"])
                    .timeout(Duration::from_secs(30)),
            )
            .await?;
        let text = result.stdout_lossy();
        let mut parts = text.split_whitespace();
        let os = parts.next().unwrap_or("linux").to_lowercase();
        let version = parts.next().unwrap_or("").to_owned();
        let arch = parts.next().unwrap_or("").to_owned();
        Ok(PlatformInfo::new(os, arch, version))
    }

    #[tracing::instrument(skip_all, fields(provider_kind = "docker", sandbox_id = %self.id), err)]
    async fn start(&self) -> Result<()> {
        self.events
            .run(
                EventSubject::sandbox(Some(self.id.clone())),
                Action::Start,
                |_| async {
                    let inspect = self
                        .docker
                        .inspect_container(self.id.as_str(), None::<InspectContainerOptions>)
                        .await
                        .map_err(|error| docker_error("inspecting container", error))?;
                    if let Some(network) = &self.network {
                        // A crash during create leaves the primary labeled
                        // and stopped, but not connected until every service
                        // is ready. Do not expose that incomplete allocation
                        // as a working sandbox on recovery.
                        let pending_connection = inspect.config.as_ref()
                            .and_then(|config| config.labels.as_ref())
                            .is_some_and(|labels| labels.contains_key(SIDECAR_NETWORK_LABEL))
                            && !inspect.network_settings.as_ref()
                                .and_then(|settings| settings.networks.as_ref())
                                .is_some_and(|networks| networks.contains_key(network));
                        if pending_connection {
                            return Err(Error::Provider(ProviderError::new(
                                docker_kind(),
                                "sandbox creation did not finish connecting its services; delete the incomplete sandbox",
                            )));
                        }
                        sidecars::set_running(&self.docker, network, true).await?;
                    }
                    if inspect.state.as_ref().and_then(|state| state.paused) == Some(true) {
                        return self
                            .docker
                            .unpause_container(self.id.as_str())
                            .await
                            .map_err(|error| docker_error("unpausing container", error));
                    }
                    // A daemon or VM crash may have ended the sandbox
                    // without running stop's one-shot cleanup. Sweep those
                    // resources before restarting it. Starting an already
                    // running sandbox must preserve its active one-shots.
                    if inspect.state.as_ref().and_then(|state| state.running) != Some(true) {
                        one_shot::sweep(&self.docker, self.id.as_str()).await?;
                    }
                    // Already-running (304) is success; a vanished container is
                    // not — start's postcondition is a running sandbox, so 404
                    // must surface, unlike stop/delete where gone is the goal.
                    match self
                        .docker
                        .start_container(self.id.as_str(), None::<StartContainerOptions<String>>)
                        .await
                    {
                        Ok(()) => Ok(()),
                        Err(error) if is_not_modified(&error) => Ok(()),
                        Err(error) if is_not_found(&error) => Err(Error::NotFound {
                            resource: ResourceKind::Sandbox,
                            id:       self.id.as_str().to_owned(),
                        }),
                        Err(error) => Err(docker_error("starting container", error)),
                    }
                },
            )
            .await
    }

    #[tracing::instrument(skip_all, fields(provider_kind = "docker", sandbox_id = %self.id), err)]
    async fn stop(&self) -> Result<()> {
        // Managed containers run the driver's own `sleep infinity` init
        // as PID1, which never installs a SIGTERM handler and (as PID1)
        // never receives the default disposition — so any stop grace is
        // waited out in full, buying nothing. Workload processes get
        // their SIGTERM-grace-SIGKILL sequence from the exec watcher,
        // not from `docker stop`. Keep the grace at fabro's 1 second.
        self.events
            .run(
                EventSubject::sandbox(Some(self.id.clone())),
                Action::Stop,
                |_| async {
                    self.forwards.close_all().await;
                    // Whatever a one-shot was doing in the workspace ends
                    // with the sandbox's own processes.
                    one_shot::sweep(&self.docker, self.id.as_str()).await?;
                    tolerate_not_modified(
                        self.docker
                            .stop_container(self.id.as_str(), Some(StopContainerOptions { t: 1 }))
                            .await,
                        "stopping container",
                    )?;
                    if let Some(network) = &self.network {
                        sidecars::set_running(&self.docker, network, false).await?;
                    }
                    Ok(())
                },
            )
            .await
    }

    #[tracing::instrument(skip_all, fields(provider_kind = "docker", sandbox_id = %self.id), err)]
    async fn delete(&self) -> Result<()> {
        let options = RemoveContainerOptions {
            force: true,
            v: true,
            ..Default::default()
        };
        self.events
            .run(
                EventSubject::sandbox(Some(self.id.clone())),
                Action::Delete,
                |_| async {
                    self.forwards.close_all().await;
                    one_shot::sweep(&self.docker, self.id.as_str()).await?;
                    if let Some(network) = &self.network {
                        sidecars::sweep(&self.docker, network, Some(self.id.as_str())).await?;
                    }
                    match self
                        .docker
                        .remove_container(self.id.as_str(), Some(options))
                        .await
                    {
                        Ok(()) => Ok(()),
                        Err(error) if is_not_found(&error) => Ok(()),
                        Err(error) => Err(docker_error("removing container", error)),
                    }
                },
            )
            .await
    }

    #[tracing::instrument(skip_all, fields(provider_kind = "docker", sandbox_id = %self.id), err)]
    async fn pause(&self) -> Result<()> {
        self.events
            .run(
                EventSubject::sandbox(Some(self.id.clone())),
                Action::Pause,
                |_| async {
                    self.docker
                        .pause_container(self.id.as_str())
                        .await
                        .map_err(|error| docker_error("pausing container", error))
                },
            )
            .await
    }

    #[tracing::instrument(skip_all, fields(provider_kind = "docker", sandbox_id = %self.id), err)]
    async fn resume(&self) -> Result<()> {
        self.events
            .run(
                EventSubject::sandbox(Some(self.id.clone())),
                Action::Resume,
                |_| async {
                    self.docker
                        .unpause_container(self.id.as_str())
                        .await
                        .map_err(|error| docker_error("unpausing container", error))
                },
            )
            .await
    }

    fn exec(&self) -> &dyn Exec {
        self.exec.as_ref()
    }

    fn fs(&self) -> &dyn Filesystem {
        &self.fs
    }

    fn pty(&self) -> Option<&dyn Pty> {
        Some(&self.pty)
    }

    fn one_shot(&self) -> Option<&dyn OneShot> {
        self.one_shot
            .as_ref()
            .map(|one_shot| one_shot as &dyn OneShot)
    }

    fn shell_command(&self) -> Option<&dyn ShellCommand> {
        Some(&self.shell_command)
    }

    fn preview_urls(&self) -> Option<&dyn PreviewUrls> {
        Some(&self.forwards)
    }
}
