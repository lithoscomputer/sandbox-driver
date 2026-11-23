use sandbox_driver::ExecSpec;
use sandbox_driver_conformance::{Commands, Conformance};
use sandbox_driver_testing::{FakeExec, FakeProvider};

#[tokio::test]
async fn new_contract_fake_passes_common_suite() {
    let fake = FakeProvider::new();
    fake.script(|spec| match spec.argv.as_slice() {
        [probe] if probe == "probe" => Some(FakeExec {
            stdout: b"workload\n".to_vec(),
            ..FakeExec::default()
        }),
        [long] if long == "long" => Some(FakeExec {
            stdout: b"ready\n".to_vec(),
            wait_for_stop: true,
            ..FakeExec::default()
        }),
        _ => None,
    });
    let catalog = fake.sandboxes();
    let peer = fake.sandboxes();
    Conformance::new(catalog.clone(), "default", Commands {
        probe:        ExecSpec::argv(["probe"]),
        probe_output: b"workload\n".to_vec(),
        long_running: ExecSpec::argv(["long"]),
    })
    .with_peer(peer.clone())
    .run()
    .await
    .assert_pass();
    peer.shutdown().await.expect("peer shutdown");
    catalog.shutdown().await.expect("shutdown");
}
