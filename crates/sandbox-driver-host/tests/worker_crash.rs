//! Killing only an embedding worker must end its Host commands and idle
//! sentinels, without a replacement worker or an explicit recovery fence.
#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::path::{Path, PathBuf};
use std::process::{self, Stdio};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::{env, future};

use nix::errno::Errno;
use nix::sys::signal::kill;
use nix::unistd::Pid;
use sandbox_driver::legacy::{
    ExecControls, ExecSpec, SandboxFilter, SandboxProvider, SandboxSource, SandboxSpec, Termination,
};
use sandbox_driver_host::HostProvider;
use tokio::process::Command;
use tokio::{fs, time};
use tokio_util::sync::CancellationToken;

const WORKER_ROOT: &str = "SANDBOX_DRIVER_TEST_WORKER_ROOT";
const IDLE_WORKER_ROOT: &str = "SANDBOX_DRIVER_TEST_IDLE_WORKER_ROOT";
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

// Re-executed like `embedded_worker`: a completed command leaves its
// sentinel idle, and the worker records that sentinel's group and waits.
#[tokio::test]
async fn embedded_idle_worker() {
    let Some(root) = env::var_os(IDLE_WORKER_ROOT).map(PathBuf::from) else {
        return;
    };
    let provider = HostProvider::new();
    let sandbox = provider
        .create(&SandboxSpec::new(SandboxSource::HostDirectory), None)
        .await
        .expect("sandbox");
    let done = sandbox
        .exec()
        .run(&ExecSpec::bash("echo $PPID"))
        .await
        .expect("completed workload");
    fs::write(root.join("sentinel.pgid"), done.stdout_lossy().trim())
        .await
        .expect("record the idle sentinel");
    future::pending::<()>().await;
}

/// Whether the sentinel leading `pgid` still exists. A sentinel is never
/// reaped while its owner lives, so a vanished pid means its owner is gone and
/// the sentinel ended and was reaped by init.
fn sentinel_exists(pgid: i32) -> bool {
    !matches!(kill(Pid::from_raw(pgid), None), Err(Errno::ESRCH))
}

#[tokio::test]
async fn an_idle_sentinel_exits_when_its_worker_dies() {
    let root = root();
    fs::create_dir_all(&root).await.expect("case directory");
    let mut worker = Command::new(env::current_exe().expect("test executable"))
        .args(["--exact", "embedded_idle_worker", "--nocapture"])
        .env(IDLE_WORKER_ROOT, &root)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .spawn()
        .expect("embedding worker");
    let pgid_file = root.join("sentinel.pgid");
    let pgid: i32 = time::timeout(Duration::from_secs(10), async {
        loop {
            let recorded = fs::read_to_string(&pgid_file).await.unwrap_or_default();
            if let Ok(pgid) = recorded.parse() {
                break pgid;
            }
            time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("the worker's command completed");
    assert!(sentinel_exists(pgid), "the provider pins the idle sentinel");
    worker
        .kill()
        .await
        .expect("SIGKILL only the worker and reap it");
    // No provider ever fences this generation. The sentinel must notice its
    // owner is gone and end its own group instead of idling forever.
    let ended = time::timeout(Duration::from_secs(10), async {
        while sentinel_exists(pgid) {
            time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    fs::remove_dir_all(root).await.expect("case cleanup");
    assert!(ended.is_ok(), "an idle sentinel outlived its worker");
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
