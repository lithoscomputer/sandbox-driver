//! Docker sidecar behavior beyond the conformance suite.
//!
//! Requires a reachable Docker daemon; tests pass trivially without one,
//! as the conformance run does.

use std::process;

use sandbox_driver::{ExecSpec, SandboxProvider, SandboxSource, SandboxSpec};
use sandbox_driver_docker::DockerProvider;

const TEST_IMAGE: &str = "ghcr.io/lithoscomputer/ubuntu-24.04:slim-df708f910111";
const SIDECAR_IMAGE: &str = "ghcr.io/fabro-sh/dhi-alpine-base:3.23-dev-2026-06-17";

fn spec_with_sidecar(name: &str, sidecar: &serde_json::Value) -> SandboxSpec {
    let mut spec = SandboxSpec::new(SandboxSource::Image {
        reference: TEST_IMAGE.to_owned(),
    });
    spec.name = Some(format!("sandbox-driver-sidecar-{name}-{}", process::id()));
    spec.provider_config = serde_json::json!({ "sidecars": [sidecar] });
    spec
}

/// A sidecar without a health check is started and not watched, so a
/// one-shot job that exits at once (a migration, say) does not fail the
/// sandbox.
#[tokio::test(flavor = "multi_thread")]
async fn a_sidecar_without_a_health_check_may_exit() {
    let Ok(provider) = DockerProvider::connect().await else {
        return;
    };
    let spec = spec_with_sidecar(
        "one-shot",
        &serde_json::json!({
            "name": "migrate",
            "image": SIDECAR_IMAGE,
            "entrypoint": ["sh", "-c", "echo migrated; exit 0"],
        }),
    );
    let sandbox = provider
        .create(&spec, None)
        .await
        .expect("a sidecar that exits cleanly does not fail create");
    sandbox.delete().await.expect("delete");
}

/// A sidecar with a health check that dies first fails `create`, and the
/// error carries the tail of its log so the cause is visible.
#[tokio::test(flavor = "multi_thread")]
async fn a_dead_health_checked_sidecar_fails_create_with_its_log() {
    let Ok(provider) = DockerProvider::connect().await else {
        return;
    };
    let spec = spec_with_sidecar(
        "dead",
        &serde_json::json!({
            "name": "db",
            "image": SIDECAR_IMAGE,
            "entrypoint": ["sh", "-c", "echo 'fatal: config missing' >&2; exit 3"],
            "health": { "cmd": "true", "interval_ms": 500 },
        }),
    );
    let error = provider
        .create(&spec, None)
        .await
        .err()
        .expect("a dead health-checked sidecar fails create");
    let message = error.to_string();
    assert!(message.contains("db"), "names the sidecar: {message}");
    assert!(
        message.contains("fatal: config missing"),
        "quotes the log tail: {message}"
    );
    if let Ok(id) = sandbox_driver::SandboxId::try_new(spec.name.clone().expect("named")) {
        let _ = provider.delete(&id, None).await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn restarted_services_are_healthy_before_work_resumes() {
    let Ok(provider) = DockerProvider::connect().await else {
        return;
    };
    let spec = spec_with_sidecar(
        "restart",
        &serde_json::json!({
            "name": "web",
            "image": SIDECAR_IMAGE,
            "entrypoint": ["sh", "-c", "sleep 1; while true; do printf 'HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nready\n' | nc -l -p 8080; done"],
            "health": {"cmd": "wget -q -O- http://127.0.0.1:8080/ready", "interval_ms": 200, "retries": 100},
        }),
    );
    let sandbox = provider.create(&spec, None).await.expect("create");
    let run = async {
        sandbox.start().await.expect("already-running start");
        sandbox.stop().await.expect("stop");
        let recovered = provider.attach(sandbox.id(), None).await.expect("reattach");
        recovered
            .start()
            .await
            .expect("restart after services are healthy");
        recovered
            .exec()
            .run(&ExecSpec::new("curl").args(["-fsS", "http://web:8080/ready"]))
            .await
            .expect("request ready service")
    }
    .await;
    sandbox.delete().await.expect("delete");
    assert!(
        run.success(),
        "service must answer as soon as start returns: {run:?}"
    );
    assert_eq!(run.stdout, b"ready\n");
}
