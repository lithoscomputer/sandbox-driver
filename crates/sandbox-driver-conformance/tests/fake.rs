use sandbox_driver::{ExecSpec, Sandboxes};
use sandbox_driver_conformance::{Commands, Conformance};
use sandbox_driver_testing::{FakeExec, FakeProvider};

/// The suite over two catalogs of one fake that answers the suite's commands.
async fn suite() -> (Conformance, [Sandboxes; 2]) {
    let fake = FakeProvider::new();
    fake.script(["probe"], FakeExec {
        stdout: b"workload\n".to_vec(),
        ..FakeExec::default()
    })
    .await;
    fake.script(["long"], FakeExec {
        stdout: b"ready\n".to_vec(),
        wait_for_stop: true,
        ..FakeExec::default()
    })
    .await;
    let catalog = fake.sandboxes();
    let peer = fake.sandboxes();
    let conformance = Conformance::new(catalog.clone(), "default", Commands {
        probe:        ExecSpec::argv(["probe"]),
        probe_output: b"workload\n".to_vec(),
        long_running: ExecSpec::argv(["long"]),
    })
    .with_peer(peer.clone());
    (conformance, [peer, catalog])
}

async fn shut_down(catalogs: [Sandboxes; 2]) {
    for catalog in catalogs {
        catalog.shutdown().await.expect("shutdown");
    }
}

#[tokio::test]
async fn new_contract_fake_passes_common_suite() {
    let (conformance, catalogs) = suite().await;
    conformance.run().await.assert_pass();
    shut_down(catalogs).await;
}

#[tokio::test]
async fn a_provider_that_reports_only_the_spec_env_fails_the_ambient_check() {
    // The fake's `env()` is the spec's own, which is empty here: it has no
    // image or host to read variables from.
    let (conformance, catalogs) = suite().await;
    let report = conformance.with_ambient_env().run().await;
    let failed: Vec<&str> = report.failures().iter().map(|result| result.name).collect();
    assert_eq!(failed, ["ambient_env"], "{report}");
    shut_down(catalogs).await;
}
