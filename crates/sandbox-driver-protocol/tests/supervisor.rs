//! Spawned plugin replacement never replays an operation or rebinds a handle.
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;
use std::{env, process};

use sandbox_driver::{
    Error, ExecControls, ExecSpec, HealthStatus, ProviderKind, SandboxProvider, SandboxSource,
    SandboxSpec,
};
use sandbox_driver_protocol::{PluginConfig, PluginSupervisor};
use tokio::process::Command;
use tokio::sync::Notify;
use tokio::task::JoinSet;
use tokio::{fs, time};

/// A provider executable `mise run plugins:build` put beside the tests.
fn provider_binary(name: &str) -> PathBuf {
    let binary = env::current_exe()
        .expect("test binary")
        .parent()
        .expect("deps directory")
        .parent()
        .expect("profile directory")
        .join(name);
    assert!(
        binary.exists(),
        "build provider binaries with mise run plugins:build first"
    );
    binary
}

#[tokio::test]
async fn dead_plugin_fails_old_work_and_concurrent_requests_share_one_replacement() {
    let supervisor = Arc::new(
        PluginSupervisor::launch(
            "sandbox-driver",
            PluginConfig::new(ProviderKind::try_new("host").expect("kind"))
                .path(provider_binary("sandbox-driver-host"))
                .dev(true)
                .inherit_env_var("PATH"),
        )
        .await
        .expect("first plugin launches"),
    );
    assert_eq!(supervisor.kind().as_str(), "host");
    assert!(supervisor.capabilities().git.supported);
    let first = supervisor.current().await.expect("first plugin");
    assert_eq!(first.number(), 1);
    assert!(
        !first.verified(),
        "dev mode launched an unpinned executable"
    );
    assert_eq!(first.health().status, HealthStatus::Ok);
    let sandbox = first
        .provider()
        .create(&SandboxSpec::new(SandboxSource::HostDirectory), None)
        .await
        .expect("sandbox");
    let directory = sandbox.working_directory().to_owned();
    let workload_pid = Arc::new(AtomicU32::new(0));
    let process = Arc::clone(&workload_pid);
    let ready = Arc::new(Notify::new());
    let started = Arc::clone(&ready);
    let handle = Arc::clone(&sandbox);
    let task = tokio::spawn(async move {
        handle
            .exec()
            .run_streaming(&ExecSpec::bash("echo $$; exec sleep 300"), ExecControls {
                sink: Some(Arc::new(move |_, bytes| {
                    process.store(
                        String::from_utf8_lossy(&bytes)
                            .trim()
                            .parse()
                            .expect("workload PID"),
                        Ordering::SeqCst,
                    );
                    started.notify_one();
                    Box::pin(async { Ok(()) })
                })),
                ..ExecControls::default()
            })
            .await
    });
    time::timeout(Duration::from_secs(10), ready.notified())
        .await
        .expect("exec started");
    let pid = first.provider().process_id().expect("child pid");
    assert!(
        Command::new("kill")
            .args(["-KILL", &pid.to_string()])
            .status()
            .await
            .expect("kill child")
            .success()
    );
    let error = time::timeout(Duration::from_secs(5), task)
        .await
        .expect("failed work returns")
        .expect("join")
        .expect_err("no replay");
    assert!(matches!(error, Error::Transport(_)));
    let workload = workload_pid.load(Ordering::SeqCst);
    assert!(workload > 0);
    assert!(
        Command::new("kill")
            .args(["-0", &workload.to_string()])
            .status()
            .await
            .expect("observe workload")
            .success(),
        "connection loss did not terminate provider work"
    );
    assert!(
        Command::new("kill")
            .args(["-KILL", &workload.to_string()])
            .status()
            .await
            .expect("clean up workload")
            .success()
    );
    let mut callers = JoinSet::new();
    for _ in 0..16 {
        let owner = Arc::clone(&supervisor);
        callers.spawn(async move { owner.current().await.expect("replacement") });
    }
    let replacement = supervisor.current().await.expect("replacement");
    while let Some(result) = callers.join_next().await {
        assert!(Arc::ptr_eq(&replacement, &result.expect("caller")));
    }
    assert_eq!(
        replacement.number(),
        2,
        "the replacement is the next generation"
    );
    assert!(first.is_closed());
    assert_ne!(replacement.provider().process_id(), Some(pid));
    assert!(
        sandbox.describe().await.is_err(),
        "old handles remain invalid"
    );
    replacement
        .provider()
        .health()
        .await
        .expect("new work succeeds");
    // The supervisor is the provider: trait calls reach the live generation.
    let provider: &dyn SandboxProvider = supervisor.as_ref();
    provider
        .health()
        .await
        .expect("the supervisor serves the provider trait");
    let listed = provider
        .list(&sandbox_driver::SandboxFilter::default())
        .await
        .expect("list through the supervisor");
    assert!(
        listed.iter().all(|status| status.id != *sandbox.id()),
        "a replacement generation starts without the dead one's registry"
    );
    supervisor.shutdown().await.expect("shutdown");
    // A shutdown ends the generation; the next call launches a numbered
    // successor rather than reviving it.
    let after_shutdown = supervisor.current().await.expect("relaunch after shutdown");
    assert_eq!(after_shutdown.number(), 3);
    supervisor.shutdown().await.expect("shutdown");
    // Abrupt plugin death does not prove provider cleanup. The test owns its
    // local workspace and removes it explicitly after observing that failure.
    fs::remove_dir_all(directory)
        .await
        .expect("remove test workspace");
}

/// A generation serves only after its backend answered the health probe:
/// the Docker plugin starts without reaching its daemon, so pointing it
/// at a socket path that exists but has no daemon behind it ends the
/// launch with the probe's report and leaves no plugin process behind.
#[tokio::test]
async fn an_unreachable_backend_ends_the_launch_with_the_health_report() {
    let directory = env::temp_dir().join(format!("sd-supervisor-{}", process::id()));
    fs::create_dir_all(&directory).await.expect("mkdir");
    let socket = directory.join("docker.sock");
    fs::write(&socket, b"")
        .await
        .expect("a file where the daemon socket would be");
    let Err(error) = PluginSupervisor::launch(
        "sandbox-driver",
        PluginConfig::new(ProviderKind::try_new("docker").expect("kind"))
            .path(provider_binary("sandbox-driver-docker"))
            .dev(true)
            .inherit_env_var("PATH")
            .env_var("DOCKER_HOST", format!("unix://{}", socket.display())),
    )
    .await
    else {
        panic!("an unreachable daemon is refused at launch");
    };
    fs::remove_dir_all(&directory).await.expect("cleanup");
    assert!(
        matches!(&error, Error::Provider(provider) if provider.code.as_deref() == Some("unreachable")),
        "{error}"
    );
    assert!(
        error
            .to_string()
            .contains("pinging the docker daemon failed"),
        "the probe's detail is the error: {error}"
    );
}

/// The supervisor answers to the kind it was configured under, whatever the
/// executable declares for itself: a host that aliases a plugin keeps one
/// name for it in records and errors.
#[tokio::test]
async fn the_supervisor_keeps_the_configured_kind() {
    let supervisor = PluginSupervisor::launch(
        "sandbox-driver",
        PluginConfig::new(ProviderKind::try_new("host-alias").expect("kind"))
            .path(provider_binary("sandbox-driver-host"))
            .dev(true)
            .inherit_env_var("PATH"),
    )
    .await
    .expect("an aliased plugin launches");
    assert_eq!(supervisor.kind().as_str(), "host-alias");
    let generation = supervisor.current().await.expect("current generation");
    assert_eq!(generation.provider().kind().as_str(), "host");
    supervisor.shutdown().await.expect("shutdown");
}
