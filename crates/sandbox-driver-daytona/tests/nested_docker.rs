//! Local transport verification plus an explicit live nested-Docker gate.

use std::env;
use std::panic::AssertUnwindSafe;
use std::path::Path;
use std::time::Duration;

use futures_util::FutureExt;
use sandbox_driver::{
    ExecControls, ExecSpec, OneShotSpec, SandboxKind, SandboxProvider, SandboxSource, SandboxSpec,
    SnapshotId,
};
use sandbox_driver_daytona::{
    DaytonaProvider, DaytonaProviderConfig, DockerExecutionTarget, NestedDockerConfig,
};
use sandbox_driver_docker::Sidecar;
use tokio::process::Command;
use tokio::time::timeout;

#[tokio::test]
async fn vm_bridge_preserves_binary_transfers_and_half_close() {
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/docker_bridge.py");
    let result = timeout(
        Duration::from_secs(20),
        Command::new("python3")
            .arg("-B")
            .arg(script)
            .kill_on_drop(true)
            .output(),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires DAYTONA_API_KEY and SANDBOX_DRIVER_DAYTONA_DIND_SNAPSHOT"]
async fn nested_job_sidecars_one_shots_and_restart_share_the_vm_lifecycle() {
    env::var("DAYTONA_API_KEY").expect("live gate requires DAYTONA_API_KEY");
    let snapshot = env::var("SANDBOX_DRIVER_DAYTONA_DIND_SNAPSHOT")
        .expect("set a VM snapshot with start-docker, Python 3, at least 2 CPU and 4 GiB");
    let provider = DaytonaProvider::connect().await.unwrap();
    let mut spec = SandboxSpec::new(SandboxSource::Snapshot {
        id: SnapshotId::try_new(snapshot).unwrap(),
    })
    .sandbox_kind(SandboxKind::VirtualMachine)
    .working_directory("/workspace");
    spec.user = Some("root".to_owned());
    spec.timers.auto_stop_after_idle = Some(Duration::ZERO);
    let mut service = Sidecar::new("service", "alpine:3.20");
    service.entrypoint = Some(vec![
        "sh".to_owned(),
        "-c".to_owned(),
        "mkdir -p /www; echo ready >/www/index.html; exec httpd -f -p 8080 -h /www".to_owned(),
    ]);
    let mut options = sandbox_driver_docker::DockerProviderConfig::default();
    options.sidecars.push(service);
    spec.provider_config = DaytonaProviderConfig {
        docker: Some(NestedDockerConfig {
            image: "alpine:3.20".to_owned(),
            target: DockerExecutionTarget::Container,
            user: None,
            options,
        }),
        ..Default::default()
    }
    .into_value();
    let sandbox = provider.create(&spec, None).await.unwrap();
    let outcome = AssertUnwindSafe(async {
        sandbox.fs().write("binary", &[0, 255, 128, 10]).await?;
        assert_eq!(sandbox.fs().read("binary").await?, [0, 255, 128, 10]);
        let result = sandbox
            .exec()
            .run_streaming(
                &ExecSpec::new("sh").args([
                    "-c",
                    "wget -qO- http://service:8080; cat /etc/alpine-release",
                ]),
                ExecControls::default(),
            )
            .await?;
        assert_eq!(result.result.exit_code, Some(0));
        assert!(result.result.stdout_lossy().contains("ready"));
        let result = sandbox
            .one_shot()
            .unwrap()
            .run(
                &OneShotSpec::registry("alpine:3.20").entrypoint("sh").args([
                    "-c",
                    "wget -qO- http://service:8080; printf kept > one-shot",
                ]),
                ExecControls::default(),
            )
            .await?;
        assert_eq!(result.result.exit_code, Some(0));
        assert_eq!(sandbox.fs().read("one-shot").await?, b"kept");
        sandbox.stop().await?;
        let attached = provider.attach(sandbox.id(), None).await?;
        attached.start().await?;
        assert_eq!(attached.fs().read("binary").await?, [0, 255, 128, 10]);
        assert_eq!(attached.fs().read("one-shot").await?, b"kept");
        Ok::<_, sandbox_driver::Error>(())
    })
    .catch_unwind()
    .await;
    let cleanup = sandbox.delete().await;
    cleanup.expect("delete the live VM even when an assertion fails");
    outcome.unwrap().unwrap();
}
