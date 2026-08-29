//! The host provider against the black-box conformance suite.

use std::sync::Arc;

use sandbox_driver::{SandboxSource, SandboxSpec};
use sandbox_driver_conformance::{Conformance, SpecFactory};
use sandbox_driver_host::HostProvider;

#[tokio::test(flavor = "multi_thread")]
async fn host_provider_passes_conformance() {
    let provider = Arc::new(HostProvider::new());
    let specs = SpecFactory::new(|| SandboxSpec::new(SandboxSource::HostDirectory));
    let report = Conformance::new(provider, specs).run().await;
    report.assert_pass();
}
