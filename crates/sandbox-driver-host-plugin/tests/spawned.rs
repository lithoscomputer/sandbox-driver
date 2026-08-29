//! The real thing: the plugin binary spawned as a child process, spoken
//! to over its stdin/stdout, passing the same conformance suite it
//! passes in-process. This is the first time the protocol crosses a
//! genuine process boundary.

use std::sync::Arc;

use sandbox_driver::{SandboxProvider, SandboxSource, SandboxSpec};
use sandbox_driver_conformance::{Conformance, SpecFactory};
use sandbox_driver_protocol::PluginProvider;
use tokio::process::Command;

fn plugin_command() -> Command {
    Command::new(env!("CARGO_BIN_EXE_sandbox-driver-host-plugin"))
}

#[tokio::test(flavor = "multi_thread")]
async fn spawned_plugin_passes_conformance() {
    let provider = PluginProvider::spawn(plugin_command())
        .await
        .expect("plugin spawns and shakes hands");
    assert_eq!(provider.kind().as_str(), "host");

    let specs = SpecFactory::new(|| SandboxSpec::new(SandboxSource::HostDirectory));
    let provider = Arc::new(provider);
    let as_provider: Arc<dyn SandboxProvider> = Arc::clone(&provider) as Arc<dyn SandboxProvider>;
    let report = Conformance::new(as_provider, specs).run().await;
    report.assert_pass();

    provider
        .shutdown()
        .await
        .expect("plugin shuts down cleanly");
}

#[tokio::test(flavor = "multi_thread")]
async fn plugin_process_exit_fails_pending_calls() {
    let provider = PluginProvider::spawn(plugin_command())
        .await
        .expect("plugin spawns and shakes hands");
    // Shut the plugin down, then observe that further calls fail rather
    // than hang.
    provider.shutdown().await.expect("shutdown succeeds");
    let outcome = provider
        .list(&sandbox_driver::SandboxFilter::default())
        .await;
    assert!(
        outcome.is_err(),
        "calls after plugin exit must fail, not hang"
    );
}
