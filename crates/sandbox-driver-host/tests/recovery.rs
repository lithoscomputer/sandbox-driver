//! Fencing a saved generation must never signal a recycled process-group id
//! and must keep new work out of a fenced generation.
#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::env;
use std::path::PathBuf;
use std::process::{self, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use sandbox_driver::legacy::{Error, ExecSpec, SandboxProvider, SandboxSource, SandboxSpec};
use sandbox_driver_host::HostProvider;
use tokio::fs;
use tokio::process::Command;

fn registry() -> PathBuf {
    env::temp_dir().join(format!(
        "host-recovery-{}-{}",
        process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos()
    ))
}

#[tokio::test(flavor = "multi_thread")]
async fn a_saved_innocent_group_is_observed_but_never_signalled() {
    let root = registry();
    let provider = HostProvider::with_registry(&root).await.expect("registry");
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
    let restart = sandbox.start().await;
    let still_alive = innocent.try_wait().expect("observe owned child").is_none();
    innocent.kill().await.expect("test owner cleans its child");
    sandbox
        .start()
        .await
        .expect("restart finishes the old fence");
    let resumed = sandbox
        .exec()
        .run(&ExecSpec::bash("exit 7"))
        .await
        .expect("new generation");
    sandbox.delete().await.expect("retry after group ended");
    fs::remove_dir_all(root).await.expect("registry cleanup");
    assert!(still_alive, "the fencer signalled an unrelated group");
    assert!(
        matches!(restart, Err(Error::Provider(ref error)) if error.code.as_deref() == Some("fence_leaked")),
        "{restart:?}"
    );
    assert_eq!(resumed.exit_code, Some(7));
    assert!(
        matches!(outcome, Err(Error::Provider(ref error)) if error.code.as_deref() == Some("fence_leaked")),
        "{outcome:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_prefenced_generation_cannot_start_another_workload() {
    let root = registry();
    let provider = HostProvider::with_registry(&root).await.expect("registry");
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
    fs::remove_dir_all(root).await.expect("registry cleanup");
    assert!(!started, "work started in a fenced generation");
}
