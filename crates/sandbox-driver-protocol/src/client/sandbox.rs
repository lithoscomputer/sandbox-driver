//! The sandbox handle and the request-shaped facets it carries: access
//! (preview URLs, SSH, web terminal, VNC), native git clone, and logs.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use sandbox_driver::{
    Capabilities, Capability, DerivedGit, Error, EventContext, Exec, Filesystem, ForkOptions, Git,
    GitBranches, GitCheckoutOptions, GitCloneOptions, GitCommit, GitCommitOptions, GitCredentials,
    GitDiffEntry, GitDiffOptions, GitFetchOptions, GitLogOptions, GitNumstat, GitPushOptions,
    GitStatus, LifecycleTimers, LogSink, LogSource, Logs, NetworkPolicy, OneShot, PlatformInfo,
    PreviewUrl, PreviewUrls, Pty, Resources, Result, Sandbox, SandboxId, SandboxSnapshotOptions,
    SandboxStatus, SnapshotId, SshAccess, SshAccessInfo, Vnc, VncConnection, WebTerminal,
};

use super::Client;
use super::exec::{SandboxExec, SandboxOneShot};
use super::fs::SandboxFs;
use super::pty::SandboxPty;
use super::streams::follow_log_stream;
use crate::methods as m;
use crate::wire::is_method_not_found;

/// Preview-URL and SSH access backed by the plugin.
pub(super) struct SandboxAccess {
    client:     Arc<Client>,
    sandbox_id: SandboxId,
}

#[async_trait]
impl PreviewUrls for SandboxAccess {
    async fn preview_url(&self, port: u16) -> Result<PreviewUrl> {
        let result: m::PreviewUrlResult = self
            .client
            .call(m::ACCESS_PREVIEW_URL, &m::PreviewUrlParams {
                sandbox_id: self.sandbox_id.as_str().to_owned(),
                port,
            })
            .await?;
        Ok(result.preview)
    }

    async fn signed_preview_url(&self, port: u16, expires_in: Duration) -> Result<PreviewUrl> {
        let result: m::PreviewUrlResult = self
            .client
            .call(m::ACCESS_SIGNED_PREVIEW_URL, &m::SignedPreviewUrlParams {
                sandbox_id: self.sandbox_id.as_str().to_owned(),
                port,
                expires_in_ms: u64::try_from(expires_in.as_millis()).unwrap_or(u64::MAX),
            })
            .await?;
        Ok(result.preview)
    }

    async fn release_preview_url(&self, port: u16) -> Result<()> {
        let outcome: Result<m::Empty> = self
            .client
            .call(m::ACCESS_PREVIEW_RELEASE, &m::PreviewUrlParams {
                sandbox_id: self.sandbox_id.as_str().to_owned(),
                port,
            })
            .await;
        match outcome {
            Ok(_) => Ok(()),
            // A plugin predating the method holds nothing for a preview
            // URL, so there is nothing to release.
            Err(error) if is_method_not_found(&error) => Ok(()),
            Err(error) => Err(error),
        }
    }
}

#[async_trait]
impl SshAccess for SandboxAccess {
    async fn ssh_access(&self, ttl: Option<Duration>) -> Result<SshAccessInfo> {
        let result: m::SshCreateResult = self
            .client
            .call(m::ACCESS_SSH_CREATE, &m::SshCreateParams {
                sandbox_id: self.sandbox_id.as_str().to_owned(),
                ttl_ms:     ttl.map(|ttl| u64::try_from(ttl.as_millis()).unwrap_or(u64::MAX)),
            })
            .await?;
        Ok(result.access)
    }

    async fn revoke_ssh_access(&self, token: &str) -> Result<()> {
        let _: m::Empty = self
            .client
            .call(m::ACCESS_SSH_REVOKE, &m::SshRevokeParams {
                sandbox_id: self.sandbox_id.as_str().to_owned(),
                token:      token.to_owned(),
            })
            .await?;
        Ok(())
    }
}

#[async_trait]
impl WebTerminal for SandboxAccess {
    async fn web_terminal_url(&self) -> Result<String> {
        let result: m::WebTerminalResult = self
            .client
            .call(m::ACCESS_WEB_TERMINAL, &m::SandboxIdParams {
                sandbox_id: self.sandbox_id.as_str().to_owned(),
            })
            .await?;
        Ok(result.url)
    }
}

#[async_trait]
impl Vnc for SandboxAccess {
    async fn vnc_connection(&self) -> Result<VncConnection> {
        let result: m::VncResult = self
            .client
            .call(m::ACCESS_VNC, &m::SandboxIdParams {
                sandbox_id: self.sandbox_id.as_str().to_owned(),
            })
            .await?;
        Ok(result.connection)
    }
}

/// A sandbox handle backed by the plugin.
pub(super) struct SandboxHandle {
    client:            Arc<Client>,
    id:                SandboxId,
    capabilities:      Capabilities,
    working_directory: String,
    runtime_directory: Option<String>,
    exec:              SandboxExec,
    git:               SandboxGit,
    one_shot:          SandboxOneShot,
    access:            SandboxAccess,
    pty:               SandboxPty,
    logs:              SandboxLogs,
    fs:                SandboxFs,
    events:            Option<EventContext>,
}

impl SandboxHandle {
    pub(super) fn new(
        client: Arc<Client>,
        id: SandboxId,
        capabilities: Capabilities,
        working_directory: String,
        runtime_directory: Option<String>,
        events: Option<EventContext>,
    ) -> Self {
        Self {
            exec: SandboxExec {
                client:     Arc::clone(&client),
                sandbox_id: id.clone(),
            },
            git: SandboxGit {
                client:            Arc::clone(&client),
                sandbox_id:        id.clone(),
                exec:              SandboxExec {
                    client:     Arc::clone(&client),
                    sandbox_id: id.clone(),
                },
                runtime_directory: runtime_directory.clone(),
            },
            one_shot: SandboxOneShot {
                client:     Arc::clone(&client),
                sandbox_id: id.clone(),
            },
            access: SandboxAccess {
                client:     Arc::clone(&client),
                sandbox_id: id.clone(),
            },
            pty: SandboxPty {
                client:     Arc::clone(&client),
                sandbox_id: id.clone(),
            },
            logs: SandboxLogs {
                client:     Arc::clone(&client),
                sandbox_id: id.clone(),
            },
            fs: SandboxFs {
                client:     Arc::clone(&client),
                sandbox_id: id.clone(),
            },
            client,
            id,
            capabilities,
            working_directory,
            runtime_directory,
            events,
        }
    }

    fn id_params(&self) -> m::SandboxIdParams {
        m::SandboxIdParams {
            sandbox_id: self.id.as_str().to_owned(),
        }
    }

    async fn simple(&self, method: &str) -> Result<()> {
        let _: m::Empty = self.client.call(method, &self.id_params()).await?;
        Ok(())
    }
}

#[async_trait]
impl Sandbox for SandboxHandle {
    fn id(&self) -> &SandboxId {
        &self.id
    }

    fn capabilities(&self) -> &Capabilities {
        &self.capabilities
    }

    async fn describe(&self) -> Result<SandboxStatus> {
        let result: m::StatusResult = self
            .client
            .call(m::SANDBOX_DESCRIBE, &self.id_params())
            .await?;
        Ok(result.status)
    }

    fn working_directory(&self) -> &str {
        &self.working_directory
    }

    async fn environment(&self) -> Result<BTreeMap<String, String>> {
        if !self.capabilities.exec.environment {
            return Err(Error::unsupported(Capability::ExecEnvironment));
        }
        let result: m::EnvironmentResult = self
            .client
            .call(m::SANDBOX_ENVIRONMENT, &self.id_params())
            .await?;
        Ok(result.environment)
    }

    fn runtime_directory(&self) -> Option<&str> {
        self.runtime_directory.as_deref()
    }

    async fn platform_info(&self) -> Result<PlatformInfo> {
        let result: m::PlatformInfoResult = self
            .client
            .call(m::SANDBOX_PLATFORM_INFO, &self.id_params())
            .await?;
        Ok(result.platform)
    }

    async fn start(&self) -> Result<()> {
        self.simple(m::SANDBOX_START).await
    }

    async fn stop(&self) -> Result<()> {
        self.simple(m::SANDBOX_STOP).await
    }

    async fn delete(&self) -> Result<()> {
        self.simple(m::SANDBOX_DELETE).await
    }

    async fn pause(&self) -> Result<()> {
        self.simple(m::SANDBOX_PAUSE).await
    }

    async fn resume(&self) -> Result<()> {
        self.simple(m::SANDBOX_RESUME).await
    }

    async fn archive(&self) -> Result<()> {
        self.simple(m::SANDBOX_ARCHIVE).await
    }

    async fn recover(&self) -> Result<()> {
        self.simple(m::SANDBOX_RECOVER).await
    }

    async fn refresh_activity(&self) -> Result<()> {
        self.simple(m::SANDBOX_REFRESH_ACTIVITY).await
    }

    async fn fork(&self, options: &ForkOptions) -> Result<Arc<dyn Sandbox>> {
        let info: m::HandleInfo = self
            .client
            .call(m::SANDBOX_FORK, &m::ForkParams {
                sandbox_id: self.id.as_str().to_owned(),
                options:    options.into(),
            })
            .await?;
        let id = info.status.id.clone();
        if let Some(context) = &self.events {
            self.client
                .event_contexts
                .lock()
                .expect("event contexts lock")
                .insert(id.as_str().to_owned(), context.clone());
        }
        Ok(Arc::new(Self::new(
            Arc::clone(&self.client),
            id,
            info.capabilities,
            info.working_directory,
            info.runtime_directory,
            self.events.clone(),
        )))
    }

    async fn resize(&self, resources: &Resources) -> Result<()> {
        let _: m::Empty = self
            .client
            .call(m::SANDBOX_RESIZE, &m::ResizeParams {
                sandbox_id: self.id.as_str().to_owned(),
                resources:  *resources,
            })
            .await?;
        Ok(())
    }

    async fn snapshot(&self, options: &SandboxSnapshotOptions) -> Result<SnapshotId> {
        let result: m::SnapshotResult = self
            .client
            .call(m::SANDBOX_SNAPSHOT, &m::SnapshotParams {
                sandbox_id: self.id.as_str().to_owned(),
                options:    options.into(),
            })
            .await?;
        SnapshotId::try_new(result.snapshot_id)
            .map_err(|error| Error::invalid_spec("snapshot_id", error.to_string()))
    }

    async fn set_timers(&self, timers: &LifecycleTimers) -> Result<()> {
        let _: m::Empty = self
            .client
            .call(m::SANDBOX_SET_TIMERS, &m::SetTimersParams {
                sandbox_id: self.id.as_str().to_owned(),
                timers:     *timers,
            })
            .await?;
        Ok(())
    }

    async fn set_labels(&self, labels: &BTreeMap<String, String>) -> Result<()> {
        let _: m::Empty = self
            .client
            .call(m::SANDBOX_SET_LABELS, &m::SetLabelsParams {
                sandbox_id: self.id.as_str().to_owned(),
                labels:     labels.clone(),
            })
            .await?;
        Ok(())
    }

    async fn update_network(&self, policy: &NetworkPolicy) -> Result<()> {
        let _: m::Empty = self
            .client
            .call(m::SANDBOX_UPDATE_NETWORK, &m::UpdateNetworkParams {
                sandbox_id: self.id.as_str().to_owned(),
                network:    policy.clone(),
            })
            .await?;
        Ok(())
    }

    fn exec(&self) -> &dyn Exec {
        &self.exec
    }

    fn fs(&self) -> &dyn Filesystem {
        &self.fs
    }

    fn provider_git(&self) -> Option<&dyn Git> {
        // A plugin whose clone is exec-derived runs exactly what the host's
        // derived git runs, so the host derives every operation itself and
        // the wire carries nothing extra. A native clone must run in the
        // plugin, so the host routes it through `git/clone`.
        self.capabilities
            .git
            .native
            .then_some(&self.git as &dyn Git)
    }

    fn one_shot(&self) -> Option<&dyn OneShot> {
        self.capabilities
            .one_shot
            .as_ref()
            .map(|_| &self.one_shot as &dyn OneShot)
    }

    fn preview_urls(&self) -> Option<&dyn PreviewUrls> {
        self.capabilities
            .access
            .preview_urls
            .then_some(&self.access as &dyn PreviewUrls)
    }

    fn ssh(&self) -> Option<&dyn SshAccess> {
        self.capabilities
            .access
            .ssh
            .then_some(&self.access as &dyn SshAccess)
    }

    fn pty(&self) -> Option<&dyn Pty> {
        self.capabilities
            .pty
            .as_ref()
            .map(|_| &self.pty as &dyn Pty)
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
            .then_some(&self.access as &dyn WebTerminal)
    }

    fn vnc(&self) -> Option<&dyn Vnc> {
        self.capabilities
            .access
            .vnc
            .then_some(&self.access as &dyn Vnc)
    }
}

/// The host side of a plugin sandbox's git facet, selected when the
/// plugin declares `git.native`: clone crosses the wire so the plugin runs
/// its native clone (Daytona's toolbox clone, say), and every other
/// operation is exec-derived here.
pub(super) struct SandboxGit {
    client:            Arc<Client>,
    sandbox_id:        SandboxId,
    exec:              SandboxExec,
    runtime_directory: Option<String>,
}

impl SandboxGit {
    fn derived(&self) -> DerivedGit<'_> {
        let git = DerivedGit::new(&self.exec);
        match self.runtime_directory.as_deref() {
            Some(runtime_directory) => git.with_runtime_directory(runtime_directory),
            None => git,
        }
    }
}

#[async_trait]
impl Git for SandboxGit {
    async fn clone_repo(
        &self,
        url: &str,
        target_path: &str,
        options: &GitCloneOptions,
    ) -> Result<()> {
        options.validate()?;
        let outcome: Result<m::Empty> = self
            .client
            .call(m::GIT_CLONE, &m::GitCloneParams {
                sandbox_id:  self.sandbox_id.as_str().to_owned(),
                url:         url.to_owned(),
                target_path: target_path.to_owned(),
                options:     options.clone(),
            })
            .await;
        match outcome {
            Ok(_) => Ok(()),
            // A plugin predating `git/clone` served git through exec only;
            // the derived clone is what such a host ran before the method
            // existed, so the fallback changes nothing for it.
            Err(error) if is_method_not_found(&error) => {
                self.derived().clone_repo(url, target_path, options).await
            }
            Err(error) => Err(error),
        }
    }

    async fn status(&self, repo_path: &str) -> Result<GitStatus> {
        self.derived().status(repo_path).await
    }

    async fn add(&self, repo_path: &str, paths: &[String]) -> Result<()> {
        self.derived().add(repo_path, paths).await
    }

    async fn commit(&self, repo_path: &str, options: &GitCommitOptions) -> Result<String> {
        self.derived().commit(repo_path, options).await
    }

    async fn push(&self, repo_path: &str, options: &GitPushOptions) -> Result<()> {
        self.derived().push(repo_path, options).await
    }

    async fn pull(&self, repo_path: &str, credentials: Option<&GitCredentials>) -> Result<()> {
        self.derived().pull(repo_path, credentials).await
    }

    async fn branches(&self, repo_path: &str) -> Result<GitBranches> {
        self.derived().branches(repo_path).await
    }

    async fn checkout(&self, repo_path: &str, options: &GitCheckoutOptions) -> Result<()> {
        self.derived().checkout(repo_path, options).await
    }

    async fn set_ambient_credentials(
        &self,
        repo_path: &str,
        credentials: Option<&GitCredentials>,
    ) -> Result<()> {
        self.derived()
            .set_ambient_credentials(repo_path, credentials)
            .await
    }

    async fn fetch(&self, repo_path: &str, options: &GitFetchOptions) -> Result<()> {
        self.derived().fetch(repo_path, options).await
    }

    async fn rev_parse(&self, repo_path: &str, revision: &str) -> Result<String> {
        self.derived().rev_parse(repo_path, revision).await
    }

    async fn is_ancestor(&self, repo_path: &str, ancestor: &str, descendant: &str) -> Result<bool> {
        self.derived()
            .is_ancestor(repo_path, ancestor, descendant)
            .await
    }

    async fn diff_entries(
        &self,
        repo_path: &str,
        options: &GitDiffOptions,
    ) -> Result<Vec<GitDiffEntry>> {
        self.derived().diff_entries(repo_path, options).await
    }

    async fn diff_numstat(
        &self,
        repo_path: &str,
        options: &GitDiffOptions,
    ) -> Result<Vec<GitNumstat>> {
        self.derived().diff_numstat(repo_path, options).await
    }

    async fn diff_patch(&self, repo_path: &str, options: &GitDiffOptions) -> Result<String> {
        self.derived().diff_patch(repo_path, options).await
    }

    async fn log(&self, repo_path: &str, options: &GitLogOptions) -> Result<Vec<GitCommit>> {
        self.derived().log(repo_path, options).await
    }

    async fn blob_sizes(&self, repo_path: &str, blobs: &[String]) -> Result<Vec<Option<u64>>> {
        self.derived().blob_sizes(repo_path, blobs).await
    }

    async fn blobs(
        &self,
        repo_path: &str,
        blobs: &[String],
        max_bytes: u64,
    ) -> Result<Vec<Option<Vec<u8>>>> {
        self.derived().blobs(repo_path, blobs, max_bytes).await
    }

    async fn config_set(&self, repo_path: &str, key: &str, value: &str) -> Result<()> {
        self.derived().config_set(repo_path, key, value).await
    }

    async fn untracked_files(&self, repo_path: &str) -> Result<Vec<String>> {
        self.derived().untracked_files(repo_path).await
    }

    async fn add_all(&self, repo_path: &str, pathspecs: &[String]) -> Result<()> {
        self.derived().add_all(repo_path, pathspecs).await
    }
}

pub(super) struct SandboxLogs {
    client:     Arc<Client>,
    sandbox_id: SandboxId,
}

#[async_trait]
impl Logs for SandboxLogs {
    async fn follow(&self, source: LogSource, sink: LogSink) -> Result<()> {
        let stream_id = self.client.next_stream_id("logs");
        let (channel, receiver) = self.client.listener.expect()?;
        follow_log_stream(
            &self.client,
            m::LOGS_FOLLOW,
            &m::LogsFollowParams {
                sandbox_id: self.sandbox_id.as_str().to_owned(),
                stream_id: stream_id.clone(),
                channel,
                source,
            },
            &stream_id,
            receiver,
            sink,
        )
        .await
    }
}
