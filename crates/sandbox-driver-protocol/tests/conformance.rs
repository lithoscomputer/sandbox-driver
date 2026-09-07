//! The conformance suite run through the JSON-RPC protocol: the Host
//! provider served as a plugin must pass exactly what it passes
//! in-process, minus the capabilities the wire does not carry in v1.

use std::sync::Arc;

use sandbox_driver::{SandboxSource, SandboxSpec};
use sandbox_driver_conformance::{Conformance, SpecFactory};
use sandbox_driver_host::HostProvider;
use sandbox_driver_protocol::{PluginProvider, serve};
use tokio::io::{duplex, split};

#[tokio::test(flavor = "multi_thread")]
#[expect(
    clippy::print_stderr,
    reason = "the per-check report is the test's evidence"
)]
async fn host_provider_passes_conformance_over_the_wire() {
    let (host_side, plugin_side) = duplex(1024 * 1024);
    let (host_read, host_write) = split(host_side);
    let (plugin_read, plugin_write) = split(plugin_side);
    tokio::spawn(serve(
        Arc::new(HostProvider::new()),
        plugin_read,
        plugin_write,
    ));
    let provider = PluginProvider::connect(host_read, host_write)
        .await
        .expect("handshake succeeds");

    let specs = SpecFactory::new(|| SandboxSpec::new(SandboxSource::HostDirectory));
    let report = Conformance::new(Arc::new(provider), specs).run().await;
    eprintln!("{report}");
    report.assert_pass();
}
