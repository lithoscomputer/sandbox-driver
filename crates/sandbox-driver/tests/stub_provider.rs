//! Exercises the public trait surface with a minimal provider that
//! implements only the required methods, verifying the compatibility
//! rule: optional methods default to `Unsupported`, optional facets to
//! `None`, and the library conveniences work over the core alone.

use std::sync::Mutex;
use std::time::Duration;

use async_trait::async_trait;
use sandbox_driver::{
    Capabilities, Capability, DirEntry, Error, Exec, ExecControls, ExecResult, ExecSpec,
    ExecStreamingResult, FileKind, FileMetadata, Filesystem, Isolation, PlatformInfo, Result,
    Sandbox, SandboxId, SandboxState, SandboxStatus, Termination, WaitOptions, activate,
    wait_for_state,
};

struct StubExec;

#[async_trait]
impl Exec for StubExec {
    async fn run(&self, spec: &ExecSpec) -> Result<ExecResult> {
        let mut result = ExecResult::new(Termination::Exited, Some(0), Duration::from_millis(1));
        if spec.args.iter().any(|arg| arg.contains("fabro-bash-ready")) {
            result.stdout = b"fabro-bash-ready".to_vec();
        }
        Ok(result)
    }

    async fn run_streaming(
        &self,
        spec: &ExecSpec,
        _controls: ExecControls,
    ) -> Result<ExecStreamingResult> {
        let result = self.run(spec).await?;
        let mut streaming = ExecStreamingResult::new(result);
        streaming.streams_separated = true;
        Ok(streaming)
    }
}

struct StubFs;

#[async_trait]
impl Filesystem for StubFs {
    async fn read(&self, _path: &str) -> Result<Vec<u8>> {
        Ok(Vec::new())
    }

    async fn write(&self, _path: &str, _content: &[u8]) -> Result<()> {
        Ok(())
    }

    async fn delete(&self, _path: &str, _recursive: bool) -> Result<()> {
        Ok(())
    }

    async fn exists(&self, _path: &str) -> Result<bool> {
        Ok(false)
    }

    async fn metadata(&self, _path: &str) -> Result<FileMetadata> {
        Ok(FileMetadata::new(FileKind::File, 0))
    }

    async fn list_dir(&self, _path: &str, _depth: usize) -> Result<Vec<DirEntry>> {
        Ok(Vec::new())
    }

    async fn create_dir(&self, _path: &str) -> Result<()> {
        Ok(())
    }

    async fn rename(&self, _from: &str, _to: &str) -> Result<()> {
        Ok(())
    }
}

struct StubSandbox {
    id:           SandboxId,
    capabilities: Capabilities,
    state:        Mutex<SandboxState>,
    exec:         StubExec,
    fs:           StubFs,
}

impl StubSandbox {
    fn new(initial: SandboxState) -> Self {
        Self {
            id:           SandboxId::try_new("stub-1").expect("valid id"),
            capabilities: Capabilities::minimal(Isolation::None),
            state:        Mutex::new(initial),
            exec:         StubExec,
            fs:           StubFs,
        }
    }

    fn set_state(&self, state: SandboxState) {
        *self.state.lock().expect("state lock") = state;
    }
}

#[async_trait]
impl Sandbox for StubSandbox {
    fn id(&self) -> &SandboxId {
        &self.id
    }

    fn capabilities(&self) -> &Capabilities {
        &self.capabilities
    }

    async fn describe(&self) -> Result<SandboxStatus> {
        let state = *self.state.lock().expect("state lock");
        Ok(SandboxStatus::new(self.id.clone(), state))
    }

    fn working_directory(&self) -> &'static str {
        "/workspace"
    }

    async fn platform_info(&self) -> Result<PlatformInfo> {
        Ok(PlatformInfo::new("linux", "aarch64", "stub"))
    }

    async fn start(&self) -> Result<()> {
        self.set_state(SandboxState::Running);
        Ok(())
    }

    async fn stop(&self) -> Result<()> {
        self.set_state(SandboxState::Stopped);
        Ok(())
    }

    async fn delete(&self) -> Result<()> {
        self.set_state(SandboxState::Deleted);
        Ok(())
    }

    fn exec(&self) -> &dyn Exec {
        &self.exec
    }

    fn fs(&self) -> &dyn Filesystem {
        &self.fs
    }
}

#[tokio::test]
async fn optional_lifecycle_methods_default_to_unsupported() {
    let sandbox = StubSandbox::new(SandboxState::Running);
    let error = sandbox.pause().await.expect_err("pause is unsupported");
    assert!(
        matches!(error, Error::Unsupported {
            capability: Capability::LifecyclePause,
        }),
        "unexpected error: {error}"
    );
    let error = sandbox.archive().await.expect_err("archive is unsupported");
    assert!(matches!(error, Error::Unsupported {
        capability: Capability::LifecycleArchive,
    }));
}

#[tokio::test]
async fn optional_facets_default_to_none() {
    let sandbox = StubSandbox::new(SandboxState::Running);
    assert!(sandbox.pty().is_none());
    assert!(sandbox.git().is_none());
    assert!(sandbox.preview_urls().is_none());
}

#[tokio::test]
async fn activate_starts_a_stopped_sandbox_and_probes_it() {
    let sandbox = StubSandbox::new(SandboxState::Stopped);
    let wait = WaitOptions {
        interval: Duration::from_millis(5),
        deadline: Some(Duration::from_secs(1)),
    };
    activate(&sandbox, &wait).await.expect("activate succeeds");
    let status = sandbox.describe().await.expect("describe succeeds");
    assert_eq!(status.state, SandboxState::Running);
}

#[tokio::test]
async fn wait_for_state_times_out_with_a_typed_error() {
    let sandbox = StubSandbox::new(SandboxState::Starting);
    let wait = WaitOptions {
        interval: Duration::from_millis(5),
        deadline: Some(Duration::from_millis(20)),
    };
    let error = wait_for_state(&sandbox, SandboxState::Running, &wait)
        .await
        .expect_err("never reaches running");
    assert!(
        matches!(error, Error::Timeout { .. }),
        "unexpected error: {error}"
    );
}

#[tokio::test]
async fn spawn_stdio_defaults_to_unsupported() {
    let exec = StubExec;
    let error = exec
        .spawn_stdio(&sandbox_driver::SpawnSpec::new("cat"))
        .await
        .expect_err("stdio is unsupported");
    assert!(matches!(error, Error::Unsupported {
        capability: Capability::ExecStdioProcess,
    }));
}
