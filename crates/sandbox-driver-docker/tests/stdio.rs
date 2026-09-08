//! Docker-specific stdio process behavior beyond the conformance suite.
//!
//! Requires a reachable Docker daemon; tests pass trivially without one,
//! as the conformance run does.

use std::sync::Arc;
use std::time::Duration;

use sandbox_driver::{ExecSpec, SandboxProvider, SandboxSource, SandboxSpec, SpawnSpec};
use sandbox_driver_docker::DockerProvider;

const TEST_IMAGE: &str = "ghcr.io/lithoscomputer/ubuntu-24.04:slim-df708f910111";

#[tokio::test(flavor = "multi_thread")]
async fn late_terminate_leaves_no_stray_stop_file() {
    let Ok(provider) = DockerProvider::connect().await else {
        return;
    };
    let spec = SandboxSpec::new(SandboxSource::Image {
        reference: TEST_IMAGE.to_owned(),
    });
    let sandbox = Arc::new(provider)
        .create(&spec, None)
        .await
        .expect("create");

    let process = sandbox
        .exec()
        .spawn_stdio(&SpawnSpec::new("true"))
        .await
        .expect("spawn");
    let (termination, _code) = process.handle.wait().await;
    assert_eq!(termination, sandbox_driver::Termination::Exited);

    // A supervisor that always terminates during cleanup must not
    // accumulate stop files for processes that already exited.
    process.handle.terminate().await;

    let listing = sandbox
        .exec()
        .run(
            &ExecSpec::bash("ls /tmp/.sandbox-driver 2>/dev/null || true")
                .timeout(Duration::from_secs(10)),
        )
        .await
        .expect("list control files");
    let stdout = listing.stdout_lossy();
    assert!(
        !stdout.contains(".stop"),
        "stray stop file after late terminate: {stdout}"
    );

    sandbox.delete().await.expect("delete");
}
