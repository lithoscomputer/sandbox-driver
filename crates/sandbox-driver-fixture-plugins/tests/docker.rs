//! Docker's runtime served as a third-party plugin (`test-docker`) and
//! reached through the loader and protocol version 3 must behave like the
//! built-in Docker provider: the shared conformance suite passes, and its
//! descriptor matches the in-process one.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use sandbox_driver::ProviderKind;
use sandbox_driver::contract::{
    CatalogOptions, Descriptor, Environment, EnvironmentName, Error, ExecSpec, ProviderEntry,
    ProviderName, Registry, SandboxSpec, Sandboxes, SecretResolver, Source, StaticEnvironments,
};
use sandbox_driver_conformance::contract::{Commands, Conformance};
use sandbox_driver_docker::DockerFactory;
use sandbox_driver_protocol::PluginLoader;
use serde_json::json;

/// The image Docker's own contract tests use.
const IMAGE: &str = "ghcr.io/fabro-sh/dhi-alpine-base:3.23-dev-2026-06-17";

struct NoSecrets;
#[async_trait]
impl SecretResolver for NoSecrets {
    async fn resolve(&self, _: &str) -> Result<Option<String>, Error> {
        Ok(None)
    }
}

/// A catalog with one entry, `docker`, serving the `default` environment.
fn catalog(entry: ProviderEntry, registry: &Registry) -> Sandboxes {
    let provider = ProviderName::try_new("docker").expect("name");
    let environments = BTreeMap::from([(
        EnvironmentName::try_new("default").expect("environment"),
        Environment {
            provider: provider.clone(),
            spec:     SandboxSpec::new(Source::Image(IMAGE.to_owned())),
        },
    )]);
    Sandboxes::try_new(
        [(provider, entry)],
        Arc::new(StaticEnvironments(environments)),
        registry,
        Arc::new(NoSecrets),
        CatalogOptions::default(),
    )
    .expect("catalog")
}

fn built_in() -> Sandboxes {
    let registry = Registry::new()
        .builtin(
            ProviderKind::try_new("docker").expect("kind"),
            Arc::new(DockerFactory),
        )
        .expect("registry");
    catalog(
        serde_json::from_value(json!({"plugin": "docker"})).expect("entry"),
        &registry,
    )
}

fn over_v3() -> Sandboxes {
    let binary = PathBuf::from(env!("CARGO_BIN_EXE_sandbox-driver-test-docker"));
    catalog(
        serde_json::from_value(json!({"plugin": "test-docker", "path": binary, "dev": true}))
            .expect("entry"),
        &Registry::new().plugins(Arc::new(PluginLoader::default())),
    )
}

async fn describe(catalog: &Sandboxes) -> Descriptor {
    catalog
        .provider("docker")
        .expect("entry")
        .describe()
        .await
        .expect("describe")
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires a live Docker daemon"]
#[expect(
    clippy::print_stderr,
    reason = "the per-check report is the test's evidence"
)]
async fn docker_over_protocol_3_matches_the_built_in() {
    let direct = built_in();
    let catalog = over_v3();
    let peer = over_v3();

    let mut expected = describe(&direct).await;
    let actual = describe(&catalog).await;
    assert_eq!(actual.schemas.kind.as_str(), "test-docker");
    expected.schemas.kind = actual.schemas.kind.clone();
    // Exemption, removed by the "Protocol 3 optional capabilities" story:
    // protocol 3 does not carry endpoints or one-shot containers yet, so it
    // masks them. The lifecycle group is leaving the contract instead.
    assert!(
        !expected.capabilities.endpoints.is_empty() && expected.capabilities.containers,
        "the exemption covers capabilities Docker really advertises"
    );
    expected.capabilities.lifecycle.clear();
    expected.capabilities.endpoints.clear();
    expected.capabilities.containers = false;
    // Everything else crosses the wire unchanged, including the namespace:
    // both reach the same daemon.
    assert_eq!(actual, expected);

    let report = Conformance::new(catalog.clone(), "default", Commands {
        probe:        ExecSpec::argv(["printf", "workload\\n"]),
        probe_output: b"workload\n".to_vec(),
        long_running: ExecSpec::argv(["sh", "-c", "echo ready; exec sleep 600"]),
    })
    .with_peer(peer.clone())
    .run()
    .await;
    eprintln!("{report}");
    report.assert_pass();
    peer.shutdown().await.expect("peer shutdown");
    catalog.shutdown().await.expect("shutdown");
    direct.shutdown().await.expect("direct shutdown");
}
