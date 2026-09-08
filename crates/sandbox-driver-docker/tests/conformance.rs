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
const TEST_IMAGE: &str = "ghcr.io/lithoscomputer/ubuntu-24.04:slim-df708f910111";
/// The one-shot image needs only a POSIX userland.
const ONE_SHOT_IMAGE: &str = "ghcr.io/fabro-sh/dhi-alpine-base:3.23-dev-2026-06-17";

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
#[expect(
    clippy::print_stderr,
    reason = "the per-check report is the test's evidence"
)]
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
#[expect(
    clippy::print_stderr,
    reason = "the per-check report is the test's evidence"
)]
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
