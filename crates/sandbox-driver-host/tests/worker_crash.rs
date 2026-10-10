//! Killing only an embedding worker must end its Host commands, without a
//! replacement worker or an explicit recovery fence.
#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::env;
use std::path::{Path, PathBuf};
use std::process::{self, Stdio};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use sandbox_driver::{
    ExecControls, ExecSpec, SandboxFilter, SandboxProvider, SandboxSource, SandboxSpec, Termination,
};
use sandbox_driver_host::HostProvider;
use tokio::process::Command;
use tokio::{fs, time};
use tokio_util::sync::CancellationToken;

const WORKER_ROOT: &str = "SANDBOX_DRIVER_TEST_WORKER_ROOT";
const DELAY: Duration = Duration::from_secs(3);

fn root() -> PathBuf {
    env::temp_dir().join(format!(
        "host-worker-crash-{}-{}",
        process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos()
    ))
}

fn delayed_writes(root: &Path) -> ExecSpec {
    // The markers are outside the sandbox workspace. The background child
    // checks that owner death stops descendants as well as the shell.
    ExecSpec::bash(format!(
        "echo $$ > '{0}/shell.pid'; (echo ready > '{0}/child.ready'; sleep 3; echo child > '{0}/child.late') & sleep 3; echo shell > '{0}/shell.late'; wait",
        root.display()
    )).no_timeout()
}

async fn started(root: &Path) {
    time::timeout(Duration::from_secs(10), async {
        while !root.join("shell.pid").exists() || !root.join("child.ready").exists() {
            time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("shell and descendant started");
}

fn has_late_writes(root: &Path) -> bool {
    root.join("shell.late").exists() || root.join("child.late").exists()
}

// Re-executed in a child so SIGKILL targets the process embedding the
// provider. Ordinary suite execution has no fixture environment and returns.
#[tokio::test]
async fn embedded_worker() {
    let Some(root) = env::var_os(WORKER_ROOT).map(PathBuf::from) else {
        return;
    };
    let provider = HostProvider::with_registry(root.join("registry"))
        .await
        .expect("registry");
    let sandbox = provider
        .create(&SandboxSpec::new(SandboxSource::HostDirectory), None)
        .await
        .expect("sandbox");
    sandbox
        .exec()
        .run(&delayed_writes(&root))
        .await
        .expect("workload");
}

#[tokio::test]
async fn worker_death_prevents_late_shell_and_descendant_writes() {
    let root = root();
    fs::create_dir_all(&root).await.expect("case directory");
    let mut worker = Command::new(env::current_exe().expect("test executable"))
        .args(["--exact", "embedded_worker", "--nocapture"])
        .env(WORKER_ROOT, &root)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .spawn()
        .expect("embedding worker");
    started(&root).await;
    worker
        .kill()
        .await
        .expect("SIGKILL only the worker and reap it");
    // No replacement provider is opened until after the delayed writes
    // would have happened. Recovery cannot make this assertion pass.
    time::sleep(DELAY + Duration::from_millis(500)).await;
    let leaked = has_late_writes(&root);
    // Fence even on failure, so a regression cannot leave work behind.
    let provider = HostProvider::with_registry(root.join("registry"))
        .await
        .expect("recovery registry");
    for sandbox in provider
        .list(&SandboxFilter::default())
        .await
        .expect("list")
    {
        provider
            .attach(&sandbox.id, None)
            .await
            .expect("attach")
            .delete()
            .await
            .expect("cleanup");
    }
    fs::remove_dir_all(root).await.expect("case cleanup");
    assert!(!leaked, "a command kept writing after its worker died");
}

#[tokio::test]
async fn a_live_owner_allows_completion_and_public_cancellation_stops_writes() {
    for cancel in [false, true] {
        let root = root();
        fs::create_dir_all(&root).await.expect("case directory");
        let provider = HostProvider::with_registry(root.join("registry"))
            .await
            .expect("registry");
        let sandbox = provider
            .create(&SandboxSpec::new(SandboxSource::HostDirectory), None)
            .await
            .expect("sandbox");
        let running = Arc::clone(&sandbox);
        let spec = delayed_writes(&root);
        let token = CancellationToken::new();
        let controls = ExecControls {
            term: Some(token.clone()),
            ..ExecControls::default()
        };
        let pending =
            tokio::spawn(async move { running.exec().run_streaming(&spec, controls).await });
        started(&root).await;
        if cancel {
            token.cancel();
        }
        let result = time::timeout(Duration::from_secs(10), pending)
            .await
            .expect("command settles")
            .expect("task")
            .expect("exec");
        if cancel {
            time::sleep(DELAY).await;
        }
        let shell_wrote = root.join("shell.late").exists();
        let child_wrote = root.join("child.late").exists();
        sandbox.delete().await.expect("cleanup");
        fs::remove_dir_all(root).await.expect("case cleanup");
        assert_eq!(
            result.result.termination,
            if cancel {
                Termination::Cancelled
            } else {
                Termination::Exited
            }
        );
        assert_eq!(shell_wrote, !cancel, "shell side effect");
        assert_eq!(child_wrote, !cancel, "descendant side effect");
    }
}
