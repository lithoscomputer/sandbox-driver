//! Docker sidecar behavior beyond the conformance suite.
//!
//! Requires a reachable Docker daemon; tests pass trivially without one,
//! as the conformance run does.

use std::process;

use sandbox_driver::{SandboxProvider, SandboxSource, SandboxSpec};
use sandbox_driver_docker::DockerProvider;

const TEST_IMAGE: &str = "buildpack-deps:noble";
const SIDECAR_IMAGE: &str = "alpine:3.20";

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
