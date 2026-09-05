//! Docker resources belong to the VM. Only their execution target is
//! exposed; stopping or deleting the VM fences the entire nested daemon.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use sandbox_driver::{
    Capabilities, Capability, DirEntry, Error, Exec, ExecControls, ExecFailure, ExecResult,
    ExecSpec, ExecStreamingResult, FileMetadata, Filesystem, OneShot, OneShotSpec, PreviewUrls,
    Pty, PtyOptions, PtySession, Result, Sandbox, SandboxId, SandboxProvider, SandboxSource,
    SandboxSpec, SpawnSpec, StdioProcess,
};
use sandbox_driver_daytona_config::{DockerExecutionTarget, NestedDockerConfig};
use sandbox_driver_docker::{BindMount, DockerProvider, docker_capabilities};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::Mutex;

use crate::{DaytonaAccess, DaytonaClient, DaytonaExec, RUNTIME_DIRECTORY, docker_transport};

pub(super) const TARGET_LABEL: &str = "sh.sandbox-driver.docker-target";
const CONTAINER_NAME: &str = "sandbox-driver-workspace";
const DOCKER_PORT: u16 = 2375;
const START_TIMEOUT: Duration = Duration::from_secs(120);
const BRIDGE: &str = include_str!("docker_bridge.py");

pub(super) struct NestedDocker {
    target:      DockerExecutionTarget,
    vm_exec:     DaytonaExec,
    access:      DaytonaAccess,
    working_dir: String,
    sandbox:     Mutex<Option<Arc<dyn Sandbox>>>,
}

impl NestedDocker {
    pub(super) fn new(
        client: &DaytonaClient,
        vm_id: &str,
        working_dir: &str,
        target: DockerExecutionTarget,
    ) -> Self {
        Self {
            target,
            vm_exec: DaytonaExec::new(Arc::clone(client), vm_id.to_owned(), working_dir.to_owned()),
            access: DaytonaAccess::new(Arc::clone(client), vm_id.to_owned()),
            working_dir: working_dir.to_owned(),
            sandbox: Mutex::new(None),
        }
    }

    pub(super) fn targets_container(&self) -> bool {
        self.target == DockerExecutionTarget::Container
    }

    pub(super) fn target(&self) -> DockerExecutionTarget {
        self.target
    }

    pub(super) fn capabilities(&self, caps: &mut Capabilities) {
        let docker = docker_capabilities();
        caps.one_shot = docker.one_shot;
        if self.targets_container() {
            caps.exec = docker.exec;
            caps.fs = docker.fs;
            caps.git = docker.git;
            caps.pty = docker.pty;
            // VM logs and remote desktop access do not describe the job
            // container. VM lifecycle and network policy still apply.
            caps.logs = None;
            caps.access.preview_urls = false;
            caps.access.signed_preview_urls = false;
            caps.access.ssh = false;
            caps.access.ssh_ttl = false;
            caps.access.ssh_revoke = false;
            caps.access.web_terminal = false;
            caps.access.vnc = false;
        }
    }

    async fn provider(&self) -> Result<DockerProvider> {
        for spec in [
            ExecSpec::new("start-docker").timeout(START_TIMEOUT),
            ExecSpec::new("python3")
                .args([
                    "-c",
                    BRIDGE,
                    &format!("{RUNTIME_DIRECTORY}/docker-bridge.lock"),
                    "/var/run/docker.sock",
                    &DOCKER_PORT.to_string(),
                ])
                .timeout(START_TIMEOUT),
        ] {
            // Job environment variables must not redirect VM bootstrap
            // commands to another Docker context or daemon.
            let spec = spec
                .env_var("DOCKER_HOST", "unix:///var/run/docker.sock")
                .env_var("DOCKER_CONTEXT", "")
                .env_var("DOCKER_TLS_VERIFY", "")
                .env_var("DOCKER_CERT_PATH", "");
            let result = self.vm_exec.run(&spec).await?;
            if !result.success() {
                return Err(Error::Exec(
                    ExecFailure::new(
                        format!("nested Docker bootstrap: {}", spec.program),
                        result.termination,
                        result.exit_code,
                        result.stdout,
                        result.stderr,
                    )
                    .with_duration(result.duration),
                ));
            }
        }
        let preview = self.access.preview_url(DOCKER_PORT).await?;
        Ok(DockerProvider::from_client(docker_transport::connect(
            preview,
        )?))
    }

    pub(super) async fn create(
        &self,
        config: &NestedDockerConfig,
        env: &BTreeMap<String, String>,
    ) -> Result<()> {
        let mut current = self.sandbox.lock().await;
        let provider = self.provider().await?;
        let mut spec = SandboxSpec::new(SandboxSource::Image {
            reference: config.image.clone(),
        });
        spec.name = Some(CONTAINER_NAME.to_owned());
        spec.working_directory = Some(self.working_dir.clone());
        spec.env.clone_from(env);
        spec.user.clone_from(&config.user);
        let mut options = config.options.clone();
        options.init = true;
        options.host_network = !self.targets_container();
        options.binds.push(BindMount {
            host:      self.working_dir.clone(),
            container: self.working_dir.clone(),
            mode:      None,
        });
        spec.provider_config = options.into_value();
        *current = Some(provider.create(&spec, None).await?);
        Ok(())
    }

    /// Clear the old token after a successful VM stop. In-flight calls
    /// have already lost their VM connection; no operation is retried.
    pub(super) async fn stopped(&self) {
        *self.sandbox.lock().await = None;
    }

    pub(super) async fn sandbox(&self) -> Result<Arc<dyn Sandbox>> {
        let mut current = self.sandbox.lock().await;
        if let Some(sandbox) = &*current {
            return Ok(Arc::clone(sandbox));
        }
        let provider = self.provider().await?;
        let id = SandboxId::try_new(CONTAINER_NAME).expect("constant sandbox name");
        let sandbox = provider.attach(&id, None).await?;
        sandbox.start().await?;
        *current = Some(Arc::clone(&sandbox));
        Ok(sandbox)
    }
}

/// The stored Daytona label. It must stay the configuration enum's own
/// serde encoding, so a label and a `provider_config` value can never
/// disagree; the tests below pin the two together.
pub(super) fn target_label(target: DockerExecutionTarget) -> &'static str {
    match target {
        DockerExecutionTarget::Container => "container",
        DockerExecutionTarget::VirtualMachine => "virtual_machine",
    }
}

pub(super) fn parse_target(label: &str) -> Result<DockerExecutionTarget> {
    match label {
        "container" => Ok(DockerExecutionTarget::Container),
        "virtual_machine" => Ok(DockerExecutionTarget::VirtualMachine),
        _ => Err(Error::invalid_spec(
            "docker-target",
            "unrecognized stored Docker execution target",
        )),
    }
}

pub(super) fn validate(config: &NestedDockerConfig, spec: &SandboxSpec) -> Result<()> {
    if config.image.trim().is_empty() {
        return Err(Error::invalid_spec(
            "provider_config.docker.image",
            "image must not be empty",
        ));
    }
    if spec.public == Some(true) {
        return Err(Error::invalid_spec(
            "public",
            "nested Docker requires private preview access",
        ));
    }
    if !config.options.binds.is_empty() || config.options.host_network {
        return Err(Error::invalid_spec(
            "provider_config.docker.options",
            "nested Docker owns workspace binds and network placement",
        ));
    }
    if config.target == DockerExecutionTarget::VirtualMachine && !config.options.sidecars.is_empty()
    {
        return Err(Error::invalid_spec(
            "provider_config.docker.options.sidecars",
            "services require a container execution target",
        ));
    }
    Ok(())
}

#[async_trait]
impl Exec for NestedDocker {
    async fn run(&self, spec: &ExecSpec) -> Result<ExecResult> {
        self.sandbox().await?.exec().run(spec).await
    }

    async fn run_streaming(
        &self,
        spec: &ExecSpec,
        controls: ExecControls,
    ) -> Result<ExecStreamingResult> {
        self.sandbox()
            .await?
            .exec()
            .run_streaming(spec, controls)
            .await
    }

    async fn spawn_stdio(&self, spec: &SpawnSpec) -> Result<StdioProcess> {
        self.sandbox().await?.exec().spawn_stdio(spec).await
    }
}

#[async_trait]
impl OneShot for NestedDocker {
    async fn run(&self, spec: &OneShotSpec, controls: ExecControls) -> Result<ExecStreamingResult> {
        self.sandbox()
            .await?
            .one_shot()
            .ok_or_else(|| Error::unsupported(Capability::OneShot))?
            .run(spec, controls)
            .await
    }
}

#[async_trait]
impl Pty for NestedDocker {
    async fn open(&self, options: &PtyOptions) -> Result<Box<dyn PtySession>> {
        self.sandbox()
            .await?
            .pty()
            .ok_or_else(|| Error::unsupported(Capability::Pty))?
            .open(options)
            .await
    }
}

#[async_trait]
impl Filesystem for NestedDocker {
    async fn read(&self, path: &str) -> Result<Vec<u8>> {
        self.sandbox().await?.fs().read(path).await
    }
    async fn read_to(
        &self,
        path: &str,
        output: &mut (dyn AsyncWrite + Unpin + Send),
    ) -> Result<()> {
        self.sandbox().await?.fs().read_to(path, output).await
    }
    async fn read_range(&self, path: &str, offset: u64, length: Option<u64>) -> Result<Vec<u8>> {
        self.sandbox()
            .await?
            .fs()
            .read_range(path, offset, length)
            .await
    }
    async fn write(&self, path: &str, content: &[u8]) -> Result<()> {
        self.sandbox().await?.fs().write(path, content).await
    }
    async fn write_from(
        &self,
        path: &str,
        input: &mut (dyn AsyncRead + Unpin + Send),
        length: u64,
    ) -> Result<()> {
        self.sandbox()
            .await?
            .fs()
            .write_from(path, input, length)
            .await
    }
    async fn write_append(&self, path: &str, content: &[u8]) -> Result<()> {
        self.sandbox().await?.fs().write_append(path, content).await
    }
    async fn delete(&self, path: &str, recursive: bool) -> Result<()> {
        self.sandbox().await?.fs().delete(path, recursive).await
    }
    async fn exists(&self, path: &str) -> Result<bool> {
        self.sandbox().await?.fs().exists(path).await
    }
    async fn metadata(&self, path: &str) -> Result<FileMetadata> {
        self.sandbox().await?.fs().metadata(path).await
    }
    async fn list_dir(&self, path: &str, depth: usize) -> Result<Vec<DirEntry>> {
        self.sandbox().await?.fs().list_dir(path, depth).await
    }
    async fn create_dir(&self, path: &str) -> Result<()> {
        self.sandbox().await?.fs().create_dir(path).await
    }
    async fn rename(&self, from: &str, to: &str) -> Result<()> {
        self.sandbox().await?.fs().rename(from, to).await
    }
    async fn set_permissions(&self, path: &str, mode: u32) -> Result<()> {
        self.sandbox().await?.fs().set_permissions(path, mode).await
    }
    async fn upload(&self, local: &Path, remote: &str) -> Result<()> {
        self.sandbox().await?.fs().upload(local, remote).await
    }
    async fn download(&self, remote: &str, local: &Path) -> Result<()> {
        self.sandbox().await?.fs().download(remote, local).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DaytonaConfig, DaytonaProvider, daytona_capabilities};

    #[test]
    fn stored_labels_are_the_configuration_encoding_and_round_trip() {
        for target in [
            DockerExecutionTarget::Container,
            DockerExecutionTarget::VirtualMachine,
        ] {
            let label = target_label(target);
            assert_eq!(
                serde_json::to_value(target).expect("plain enum"),
                serde_json::Value::String(label.to_owned()),
                "the Daytona label and provider_config encodings disagree"
            );
            assert_eq!(parse_target(label).expect("own label"), target);
        }
    }

    #[tokio::test]
    async fn previews_are_only_available_for_the_vm_execution_target() {
        let provider = DaytonaProvider::connect_with_config(DaytonaConfig {
            api_key: Some("test-key".to_owned()),
            api_url: Some("https://daytona.example/api".to_owned()),
            ..DaytonaConfig::default()
        })
        .await
        .unwrap();
        for target in [
            DockerExecutionTarget::Container,
            DockerExecutionTarget::VirtualMachine,
        ] {
            let nested = NestedDocker::new(&provider.client, "test-vm", "/workspace", target);
            let mut caps = daytona_capabilities();
            nested.capabilities(&mut caps);
            let vm = target == DockerExecutionTarget::VirtualMachine;
            assert_eq!(caps.supports(Capability::PreviewUrls), vm);
            assert_eq!(caps.supports(Capability::SignedPreviewUrls), vm);
        }
    }
}
