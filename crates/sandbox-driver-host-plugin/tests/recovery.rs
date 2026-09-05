//! Real plugin crashes must leave recoverable records and must never make a
//! saved, recycled process-group id safe to signal.
#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::env;
use std::path::{Path, PathBuf};
use std::process::{self, Stdio};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use sandbox_driver::{Error, ExecSpec, SandboxFilter, SandboxProvider, SandboxSource, SandboxSpec};
use sandbox_driver_protocol::PluginProvider;
use tokio::process::{Child, Command};
use tokio::{fs, time};

fn registry() -> PathBuf {
    env::temp_dir().join(format!(
        "host-plugin-recovery-{}-{}",
        process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos()
    ))
}

async fn connect(root: &Path) -> (PluginProvider, Child) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_sandbox-driver-host"))
        .env("SANDBOX_DRIVER_HOST_REGISTRY", root)
        .env("RUST_LOG", "error")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .expect("spawn plugin");
    let provider = PluginProvider::connect(
        child.stdout.take().expect("stdout"),
        child.stdin.take().expect("stdin"),
    )
    .await
    .expect("connect");
    (provider, child)
}

async fn wait_for_file(path: &Path) {
    time::timeout(Duration::from_secs(10), async {
        loop {
            if fs::metadata(path).await.is_ok_and(|m| m.len() > 0) {
                break;
            }
            time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("workload started");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_plugin_crash_preserves_identity_and_stop_fences_surviving_work() {
    let root = registry();
    let (provider, mut child) = connect(&root).await;
    let sandbox = provider
        .create(
            &{
                let mut spec = SandboxSpec::new(SandboxSource::HostDirectory)
                    .label("run", "recovery")
                    .working_directory(root.join("named-workspace").to_string_lossy());
                spec.workspace_ownership = Some(sandbox_driver::WorkspaceOwnership::Managed);
                spec
            },
            None,
        )
        .await
        .expect("create");
    let id = sandbox.id().clone();
    let workspace = PathBuf::from(sandbox.working_directory());
    sandbox
        .fs()
        .write("binary", &[0, 255, 128, 10])
        .await
        .expect("binary write");
    let old = sandbox
        .exec()
        .run(&ExecSpec::bash("exit 5"))
        .await
        .expect("old status");
    assert_eq!(old.exit_code, Some(5));
    let running = Arc::clone(&sandbox);
    let pending = tokio::spawn(async move {
        running
            .exec()
            .run(
                &ExecSpec::bash("while :; do echo tick >> heartbeat; sleep 0.05; done")
                    .no_timeout(),
            )
            .await
    });
    let heartbeat = workspace.join("heartbeat");
    wait_for_file(&heartbeat).await;
    child
        .kill()
        .await
        .expect("crash plugin and reap its owned child");
    let failed = time::timeout(Duration::from_secs(5), pending)
        .await
        .expect("pending call ends")
        .expect("task");
    assert!(
        failed.is_err(),
        "an interrupted call is never reported as complete"
    );

    let (fresh, mut child) = connect(&root).await;
    let mut filter = SandboxFilter::default();
    filter
        .labels
        .insert("run".to_owned(), "recovery".to_owned());
    let found = fresh.list(&filter).await.expect("durable list");
    let attached = fresh.attach(&id, None).await.expect("durable attach");
    attached.stop().await.expect("fence old work");
    let stopped_size = fs::metadata(&heartbeat).await.expect("heartbeat").len();
    time::sleep(Duration::from_millis(350)).await;
    let final_size = fs::metadata(&heartbeat).await.expect("heartbeat").len();
    attached.start().await.expect("new generation");
    let bytes = attached
        .fs()
        .read("binary")
        .await
        .expect("retained workspace");
    let result = attached
        .exec()
        .run(&ExecSpec::bash("sleep 0.2; exit 7"))
        .await
        .expect("new status");
    attached
        .delete()
        .await
        .expect("delete managed workspace after stopping work");
    let remaining = fresh
        .list(&filter)
        .await
        .expect("deleted resource is absent");
    fresh.shutdown().await.expect("shutdown");
    child
        .kill()
        .await
        .expect("reap the externally owned plugin child");
    fs::remove_dir_all(&root).await.expect("registry cleanup");
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].id, id);
    assert_eq!(
        stopped_size, final_size,
        "stop returned while old work was writing"
    );
    assert_eq!(bytes, [0, 255, 128, 10]);
    assert_eq!(
        result.exit_code,
        Some(7),
        "a stale status must not resolve new work"
    );
    assert!(remaining.is_empty());
    assert!(!workspace.exists());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_saved_innocent_group_is_observed_but_never_signalled() {
    let root = registry();
    let (provider, mut child) = connect(&root).await;
    let sandbox = provider
        .create(&SandboxSpec::new(SandboxSource::HostDirectory), None)
        .await
        .expect("create");
    let mut innocent = Command::new("sleep")
        .arg("30")
        .process_group(0)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .expect("innocent group");
    let fake = root.join(sandbox.id().as_str()).join("groups").join("gone");
    fs::create_dir_all(&fake)
        .await
        .expect("fake old generation");
    fs::write(
        fake.join("0.group"),
        innocent.id().expect("owned child id").to_string(),
    )
    .await
    .expect("saved id");
    let outcome = sandbox.stop().await;
    let still_alive = innocent.try_wait().expect("observe owned child").is_none();
    innocent.kill().await.expect("test owner cleans its child");
    sandbox.delete().await.expect("retry after group ended");
    provider.shutdown().await.expect("shutdown");
    child
        .kill()
        .await
        .expect("reap the externally owned plugin child");
    fs::remove_dir_all(root).await.expect("registry cleanup");
    assert!(still_alive, "the fencer signalled an unrelated group");
    assert!(
        matches!(outcome, Err(Error::Provider(ref error)) if error.code.as_deref() == Some("fence_leaked")),
        "{outcome:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_prefenced_generation_cannot_start_another_workload() {
    let root = registry();
    let (provider, mut child) = connect(&root).await;
    let sandbox = provider
        .create(&SandboxSpec::new(SandboxSource::HostDirectory), None)
        .await
        .expect("create");
    sandbox
        .exec()
        .run(&ExecSpec::bash("exit 0"))
        .await
        .expect("first workload");
    let mut generations = fs::read_dir(root.join(sandbox.id().as_str()).join("groups"))
        .await
        .expect("generations");
    let generation = generations
        .next_entry()
        .await
        .expect("entry")
        .expect("one generation")
        .path();
    fs::write(generation.join("fenced"), b"")
        .await
        .expect("pre-fence");
    sandbox
        .exec()
        .run(&ExecSpec::bash("echo started > started"))
        .await
        .expect("fenced exec ends");
    let started = PathBuf::from(sandbox.working_directory())
        .join("started")
        .exists();
    sandbox.delete().await.expect("delete");
    provider.shutdown().await.expect("shutdown");
    child
        .kill()
        .await
        .expect("reap the externally owned plugin child");
    fs::remove_dir_all(root).await.expect("registry cleanup");
    assert!(!started, "work started in a fenced generation");
}
