//! The docker provider against the black-box conformance suite, in
//! process and served over the plugin protocol.
//!
//! Requires a reachable Docker daemon; the tests are skipped (pass
//! trivially) when none is available so non-Docker CI hosts stay green.

use std::sync::Arc;

use sandbox_driver::{SandboxProvider, SandboxSource, SandboxSpec};
use sandbox_driver_conformance::{Conformance, SpecFactory};
use sandbox_driver_docker::DockerProvider;
use sandbox_driver_protocol::{PluginProvider, serve};
use tokio::io::{duplex, split};

/// The conformance image must satisfy the provider's documented data-plane
/// contract, including `git` for the normalized Git facet.
const TEST_IMAGE: &str = "buildpack-deps:noble";
/// The one-shot image needs only a POSIX userland.
const ONE_SHOT_IMAGE: &str = "alpine:3.20";

fn specs() -> SpecFactory {
    SpecFactory::new(|| {
        SandboxSpec::new(SandboxSource::Image {
            reference: TEST_IMAGE.to_owned(),
        })
        .working_directory("/workspace/sandbox-driver-conformance")
    })
    .with_one_shot_image(ONE_SHOT_IMAGE)
}

#[tokio::test(flavor = "multi_thread")]
async fn docker_provider_passes_conformance() {
    let Ok(provider) = DockerProvider::connect().await else {
        // No Docker daemon on this machine; nothing to verify.
        return;
    };
    let report = Conformance::new(Arc::new(provider), specs()).run().await;
    eprintln!("{report}");
    report.assert_pass();
}

/// The same battery through the wire: what a host that links no provider
/// crate — Petri — actually exercises.
#[tokio::test(flavor = "multi_thread")]
async fn docker_provider_passes_conformance_over_the_wire() {
    let Ok(provider) = DockerProvider::connect().await else {
        return;
    };
    let (host_side, plugin_side) = duplex(1024 * 1024);
    let (host_read, host_write) = split(host_side);
    let (plugin_read, plugin_write) = split(plugin_side);
    tokio::spawn(serve(Arc::new(provider), plugin_read, plugin_write));
    let remote = PluginProvider::connect(host_read, host_write)
        .await
        .expect("handshake succeeds");
    assert_eq!(remote.kind().as_str(), "docker");
    assert!(remote.capabilities().one_shot.is_some());
    assert!(remote.capabilities().exec.stdin_stream);
    assert!(remote.capabilities().exec.environment);
    let report = Conformance::new(Arc::new(remote), specs()).run().await;
    eprintln!("{report}");
    report.assert_pass();
}
