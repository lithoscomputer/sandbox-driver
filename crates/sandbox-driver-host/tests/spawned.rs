//! The real thing: the plugin binary spawned as a child process, spoken
//! to over its stdin/stdout, passing the same conformance suite it
//! passes in-process. This is the first time the protocol crosses a
//! genuine process boundary.

use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use sandbox_driver::{SandboxProvider, SandboxSource, SandboxSpec};
use sandbox_driver_conformance::{Conformance, SpecFactory};
use sandbox_driver_protocol::PluginProvider;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;
use tokio::time;

fn plugin_command() -> Command {
    Command::new(env!("CARGO_BIN_EXE_sandbox-driver-host"))
}

#[tokio::test]
async fn shutdown_exits_while_the_request_pipe_stays_open() {
    // Sample the scheduling boundary that used to start a blocking stdin
    // read after shutdown. The client keeps its pipe open in every round.
    for _ in 0..16 {
        let mut child = plugin_command()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .expect("plugin");
        let mut requests = child.stdin.take().expect("stdin");
        let mut replies = BufReader::new(child.stdout.take().expect("stdout")).lines();
        requests
            .write_all(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"shutdown\",\"params\":{}}\n")
            .await
            .expect("shutdown request");
        let reply = time::timeout(Duration::from_secs(2), replies.next_line())
            .await
            .expect("shutdown acknowledgment arrives")
            .expect("read response")
            .expect("shutdown response");
        assert!(reply.contains("\"result\":null"), "{reply}");
        let status = time::timeout(Duration::from_secs(2), child.wait())
            .await
            .expect("plugin exits without waiting for stdin EOF")
            .expect("wait");
        assert!(status.success(), "{status}");
        drop(requests);
    }
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
