//! The docker provider against the black-box conformance suite.
//!
//! Requires a reachable Docker daemon; the test is skipped (passes
//! trivially) when none is available so non-Docker CI hosts stay green.

use std::sync::Arc;

use sandbox_driver::{SandboxSource, SandboxSpec};
use sandbox_driver_conformance::{Conformance, SpecFactory};
use sandbox_driver_docker::DockerProvider;

/// The conformance image must satisfy the provider's documented data-plane
/// contract, including `git` for the normalized Git facet.
const TEST_IMAGE: &str = "buildpack-deps:noble";

#[tokio::test(flavor = "multi_thread")]
async fn docker_provider_passes_conformance() {
    let Ok(provider) = DockerProvider::connect().await else {
        // No Docker daemon on this machine; nothing to verify.
        return;
    };
    let specs = SpecFactory::new(|| {
        SandboxSpec::new(SandboxSource::Image {
            reference: TEST_IMAGE.to_owned(),
        })
        .working_directory("/workspace/sandbox-driver-conformance")
    });
    let report = Conformance::new(Arc::new(provider), specs).run().await;
    report.assert_pass();
}
