//! Explicit live conformance over JSON-RPC. Set DAYTONA_API_KEY,
//! DAYTONA_TARGET and SANDBOX_DRIVER_DAYTONA_CONFORMANCE_SNAPSHOT.
//! The snapshot must already exist in that region. Optional
//! SANDBOX_DRIVER_DAYTONA_CONFORMANCE_DOCKER selects `container` or `process`
//! execution with nested Docker; omit it for native Daytona operations.
//! Nested Docker requires start-docker and Python 3 in the snapshot.
//! Set SANDBOX_DRIVER_DAYTONA_CONFORMANCE_CHECK to rerun one named check.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::{env, process};

use sandbox_driver::{SandboxFilter, SandboxProvider, SandboxSource, SandboxSpec, SnapshotId};
use sandbox_driver_conformance::{Conformance, SpecFactory};
use sandbox_driver_daytona_config::{
    DaytonaProviderConfig, DockerExecutionTarget, NestedDockerConfig,
};
use sandbox_driver_docker_config::DockerProviderConfig;
use sandbox_driver_protocol::PluginProvider;
use tokio::process::Command;

mod support;

const RUN_LABEL: &str = "sandbox-driver-conformance-run";

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires a regional Daytona snapshot and credentials; creates many ephemeral sandboxes"]
async fn spawned_daytona_passes_conformance() {
    support::init_diagnostics();
    env::var("DAYTONA_API_KEY").expect("live gate requires DAYTONA_API_KEY");
    let region = env::var("DAYTONA_TARGET").expect("live gate requires DAYTONA_TARGET");
    let snapshot = SnapshotId::try_new(
        env::var("SANDBOX_DRIVER_DAYTONA_CONFORMANCE_SNAPSHOT")
            .expect("live gate requires SANDBOX_DRIVER_DAYTONA_CONFORMANCE_SNAPSHOT"),
    )
    .expect("valid snapshot id");
    let docker = match env::var("SANDBOX_DRIVER_DAYTONA_CONFORMANCE_DOCKER").as_deref() {
        Err(env::VarError::NotPresent) => None,
        Ok("container") => Some(DockerExecutionTarget::Container),
        Ok("process") => Some(DockerExecutionTarget::VirtualMachine),
        _ => panic!("SANDBOX_DRIVER_DAYTONA_CONFORMANCE_DOCKER must be container or process"),
    };
    let run = format!(
        "{}-{}",
        process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after epoch")
            .as_nanos()
    );

    let mut command = Command::new(env!("CARGO_BIN_EXE_sandbox-driver-daytona"));
    command.env_clear();
    for key in [
        "PATH",
        "HOME",
        "RUST_LOG",
        "DAYTONA_API_KEY",
        "DAYTONA_API_URL",
        "DAYTONA_TARGET",
    ] {
        if let Some(value) = env::var_os(key) {
            command.env(key, value);
        }
    }
    let provider = Arc::new(PluginProvider::spawn(command).await.expect("spawn plugin"));
    let status = provider
        .snapshots()
        .expect("Daytona snapshots")
        .get(&snapshot)
        .await
        .expect("read snapshot placement and resources");
    assert!(
        status.regions.contains(&region),
        "snapshot must be in {region}"
    );
    let resources = status.resources.expect("snapshot reports resources");
    let kind = status.sandbox_kind.expect("snapshot reports kind");
    tracing::info!(%run, %region, ?resources, ?kind, ?docker, "live JSON-RPC conformance");

    let mut spec = SandboxSpec::new(SandboxSource::Snapshot { id: snapshot })
        .sandbox_kind(kind)
        .region(region.clone())
        .working_directory("/workspace/sandbox-driver-conformance")
        .label(RUN_LABEL, &run)
        .ephemeral(true);
    spec.user = Some("root".to_owned());
    if let Some(target) = docker {
        spec.provider_config = DaytonaProviderConfig {
            docker: Some(NestedDockerConfig {
                image: "buildpack-deps:noble-scm".to_owned(),
                target,
                user: None,
                options: DockerProviderConfig::default(),
            }),
            ..Default::default()
        }
        .into_value();
    }
    // Check the actual allocation before running any capability checks.
    let probe = provider
        .create(&spec, None)
        .await
        .expect("create allocation probe");
    let observed = probe.describe().await;
    probe.delete().await.expect("delete allocation probe");
    let observed = observed.expect("describe allocation probe");
    assert_eq!(observed.region.as_deref(), Some(region.as_str()));
    assert_eq!(observed.resources, Some(resources));
    tracing::info!(?observed.resources, ?observed.region, "allocation verified");

    let log_run = run.clone();
    let specs = SpecFactory::new(move || spec.clone())
        .with_git_clone_url("https://github.com/octocat/Hello-World.git")
        .with_one_shot_image("alpine:3.20")
        // Entrypoint logs belong to the outer Daytona sandbox. Nested
        // container handles do not expose logs from the job container.
        .with_entrypoint_logs(move || {
            SandboxSpec::new(SandboxSource::Dockerfile {
                content: concat!(
                    "FROM debian:stable-slim\n",
                    "ENTRYPOINT [\"/bin/sh\", \"-c\", \"echo conformance-entrypoint; ",
                    "echo conformance-entrypoint-error >&2; exec sleep 600\"]\n",
                )
                .to_owned(),
            })
            .sandbox_kind(kind)
            .region(region.clone())
            .resources(resources)
            .label(RUN_LABEL, &log_run)
            .ephemeral(true)
        });
    let as_provider: Arc<dyn SandboxProvider> = provider.clone();
    let mut conformance = Conformance::new(as_provider, specs);
    conformance.check_timeout = Duration::from_secs(900);
    conformance.wait.deadline = Some(Duration::from_secs(300));
    let selected = env::var("SANDBOX_DRIVER_DAYTONA_CONFORMANCE_CHECK").ok();
    let report = conformance
        .run_matching(|name| selected.as_deref().is_none_or(|selected| selected == name))
        .await;
    tracing::info!(%report, "conformance complete");

    // A check timeout drops its future before its normal cleanup can run.
    let mut filter = SandboxFilter::default();
    filter.labels.insert(RUN_LABEL.to_owned(), run);
    for sandbox in provider
        .list(&filter)
        .await
        .expect("list leftover fixtures")
    {
        provider
            .delete(&sandbox.id, None)
            .await
            .expect("delete leftover fixture");
    }
    provider
        .shutdown()
        .await
        .expect("plugin shuts down cleanly");
    assert!(
        !report.results.is_empty(),
        "the check name must match a conformance check"
    );
    report.assert_pass();
}
