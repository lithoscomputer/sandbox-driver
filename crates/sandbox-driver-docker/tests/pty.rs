//! Docker-specific PTY behavior beyond the conformance suite.
//!
//! Requires a reachable Docker daemon; tests pass trivially without one,
//! as the conformance run does.

use std::sync::Arc;
use std::time::Duration;

use sandbox_driver::{ExecSpec, PtyOptions, SandboxProvider, SandboxSource, SandboxSpec};
use sandbox_driver_docker::DockerProvider;
use tokio::time;

const TEST_IMAGE: &str = "ghcr.io/lithoscomputer/ubuntu-24.04:slim-df708f910111";

#[tokio::test(flavor = "multi_thread")]
async fn close_kills_a_shell_that_ignores_term() {
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

    let pty = sandbox.pty().expect("pty facet");
    let session = pty.open(&PtyOptions::default()).await.expect("open pty");
    // Make the interactive shell ignore TERM, so only the KILL
    // escalation can end it.
    session
        .write_input(b"trap '' TERM\n")
        .await
        .expect("write trap");
    time::sleep(Duration::from_millis(300)).await;
    session.close().await.expect("close");

    // The interactive `sh -l` must be gone; the container's only
    // long-lived process is its `sleep infinity` init. Match on the
    // arguments, because the exec wrapper running this listing is a
    // `sh -c` itself.
    let listing = sandbox
        .exec()
        .run(
            &ExecSpec::bash("ps -e -o args= | grep -c '^sh -l' || true")
                .timeout(Duration::from_secs(10)),
        )
        .await
        .expect("list processes");
    assert_eq!(
        listing.stdout_lossy().trim(),
        "0",
        "surviving shells: {}",
        listing.stdout_lossy()
    );

    sandbox.delete().await.expect("delete");
}
