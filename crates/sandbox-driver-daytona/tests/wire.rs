//! Daytona served over the JSON-RPC protocol: the full conformance
//! suite — including the volume round trip and access-facet consistency
//! — must hold through the wire exactly as it holds in-process.
//!
//! Live test: requires `DAYTONA_API_KEY`; skipped otherwise.

use std::env;
use std::sync::Arc;
use std::time::Duration;

use sandbox_driver::{SandboxSource, SandboxSpec};
use sandbox_driver_conformance::{Conformance, SpecFactory};
use sandbox_driver_daytona::DaytonaProvider;
use sandbox_driver_protocol::{PluginProvider, serve};
use tokio::io::{duplex, split};

const TEST_SNAPSHOT: &str = "daytona-medium";

#[tokio::test(flavor = "multi_thread")]
async fn daytona_passes_conformance_over_the_wire() {
    if env::var("DAYTONA_API_KEY").is_err() {
        // No credentials; nothing to verify.
        return;
    }
    let provider = DaytonaProvider::connect()
        .await
        .expect("connect with credentials");
    let (host_side, plugin_side) = duplex(1024 * 1024);
    let (host_read, host_write) = split(host_side);
    let (plugin_read, plugin_write) = split(plugin_side);
    tokio::spawn(serve(Arc::new(provider), plugin_read, plugin_write));
    let remote = PluginProvider::connect(host_read, host_write)
        .await
        .expect("handshake");

    let specs = SpecFactory::new(|| {
        SandboxSpec::new(SandboxSource::Snapshot {
            name: TEST_SNAPSHOT.to_owned(),
        })
        .ephemeral(true)
    });
    let mut conformance = Conformance::new(Arc::new(remote), specs);
    conformance.check_timeout = Duration::from_secs(900);
    conformance.wait.deadline = Some(Duration::from_secs(300));
    let report = conformance.run().await;
    report.assert_pass();
}
