//! A handle reapplies the container's configured environment past the
//! exec wrapper's `/bin/sh`, whether `create` or `attach` built it.
//!
//! Requires a reachable Docker daemon; tests pass trivially without one,
//! as the conformance run does.

use std::sync::Arc;
use std::time::Duration;

use sandbox_driver::{
    BASH_ENV_VAR, ExecSpec, Sandbox, SandboxProvider, SandboxSource, SandboxSpec, SpawnSpec,
};
use sandbox_driver_docker::DockerProvider;
use tokio::io::AsyncReadExt;

const TEST_IMAGE: &str = "ghcr.io/lithoscomputer/ubuntu-24.04:slim-df708f910111";

async fn stdout_of(sandbox: &dyn Sandbox, spec: ExecSpec) -> String {
    let result = sandbox
        .exec()
        .run(&spec.timeout(Duration::from_secs(30)))
        .await
        .expect("exec runs");
    assert!(result.success(), "exec failed: {result:?}");
    result.stdout_lossy()
}

/// `IFS` is the canary: a POSIX shell resets it on startup, so a value
/// that reaches the command must have been reapplied after the wrapper
/// shell started, not merely inherited from the container.
#[tokio::test(flavor = "multi_thread")]
async fn attached_handles_reapply_the_configured_env_like_created_ones() {
    let Ok(provider) = DockerProvider::connect().await else {
        return;
    };
    let provider = Arc::new(provider);
    let spec = SandboxSpec::new(SandboxSource::Image {
        reference: TEST_IMAGE.to_owned(),
    })
    .env_var("IFS", "x")
    .env_var("SANDBOX_DRIVER_MARKER", "configured")
    .env_var(BASH_ENV_VAR, "/nonexistent-startup-file");
    let created = provider.create(&spec, None).await.expect("create");
    let attached = provider.attach(created.id(), None).await.expect("attach");

    for (how, sandbox) in [("created", &created), ("attached", &attached)] {
        let printenv = |var: &str| ExecSpec::new("printenv").arg(var);
        assert_eq!(
            stdout_of(sandbox.as_ref(), printenv("IFS")).await,
            "x\n",
            "{how} handle: the shell-reset IFS is reapplied"
        );
        assert_eq!(
            stdout_of(sandbox.as_ref(), printenv("SANDBOX_DRIVER_MARKER")).await,
            "configured\n",
            "{how} handle: an ordinary configured variable reaches the command"
        );
        assert_eq!(
            stdout_of(sandbox.as_ref(), printenv("IFS").env_var("IFS", "y")).await,
            "y\n",
            "{how} handle: a per-command override wins over the configured value"
        );
        assert_eq!(
            stdout_of(sandbox.as_ref(), printenv(BASH_ENV_VAR)).await,
            "\n",
            "{how} handle: BASH_ENV stays blank"
        );

        let mut process = sandbox
            .exec()
            .spawn_stdio(&SpawnSpec::new("printenv").arg("IFS"))
            .await
            .expect("spawn");
        let mut stdout = String::new();
        process
            .stdout
            .read_to_string(&mut stdout)
            .await
            .expect("read stdio stdout");
        let (termination, code) = process.handle.wait().await;
        assert_eq!(termination, sandbox_driver::Termination::Exited);
        assert_eq!(code, Some(0));
        assert_eq!(stdout, "x\n", "{how} handle: stdio reapplies IFS too");
    }

    created.delete().await.expect("delete");
}
