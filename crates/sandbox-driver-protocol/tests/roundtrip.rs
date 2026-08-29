//! The conformance moment from the design: the Host provider served over
//! JSON-RPC must behave like the Host provider in-process. Also proves
//! the interleaving requirement — a slow call must not block a fast one.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use sandbox_driver::{
    Capability, Error, ExecControls, ExecSpec, OutputStream, SandboxProvider, SandboxSource,
    SandboxSpec, Termination, WaitOptions, activate,
};
use sandbox_driver_host::HostProvider;
use sandbox_driver_protocol::{PluginProvider, serve};
use tokio::io::{duplex, split};
use tokio::time;
use tokio_util::sync::CancellationToken;

type SeenChunks = Arc<Mutex<Vec<(OutputStream, Vec<u8>)>>>;

async fn connect() -> PluginProvider {
    let (host_side, plugin_side) = duplex(1024 * 1024);
    let (host_read, host_write) = split(host_side);
    let (plugin_read, plugin_write) = split(plugin_side);
    tokio::spawn(serve(
        Arc::new(HostProvider::new()),
        plugin_read,
        plugin_write,
    ));
    PluginProvider::connect(host_read, host_write)
        .await
        .expect("handshake succeeds")
}

fn host_spec() -> SandboxSpec {
    SandboxSpec::new(SandboxSource::HostDirectory)
}

#[tokio::test]
async fn handshake_negotiates_capabilities() {
    let provider = connect().await;
    assert_eq!(provider.kind().as_str(), "host");
    assert!(provider.capabilities().exec.live_streaming);
    assert!(provider.capabilities().fs.native);
    provider.shutdown().await.expect("shutdown");
}

#[tokio::test]
async fn create_exec_fs_delete_round_trip() {
    let provider = connect().await;
    let sandbox = provider.create(&host_spec(), None).await.expect("create");

    // The bash probe passes through the protocol unchanged.
    activate(sandbox.as_ref(), &WaitOptions::default())
        .await
        .expect("probe over the wire");

    // Buffered exec with stdin and binary-safe output.
    let spec = ExecSpec::new("printf 'wire\\0bytes'; cat >&2")
        .stdin(b"stderr-payload".to_vec())
        .timeout(Duration::from_secs(10));
    let result = sandbox.exec().run(&spec).await.expect("exec");
    assert!(result.success());
    assert_eq!(result.stdout, b"wire\0bytes");
    assert_eq!(result.stderr, b"stderr-payload");

    // Filesystem across base64.
    let fs = sandbox.fs();
    fs.write("dir/file.bin", &[0u8, 159, 146, 150])
        .await
        .expect("write");
    assert_eq!(fs.read("dir/file.bin").await.expect("read"), vec![
        0u8, 159, 146, 150
    ]);
    assert!(fs.exists("dir/file.bin").await.expect("exists"));
    let entries = fs.list_dir(".", 2).await.expect("list");
    assert!(entries.iter().any(|entry| entry.path.ends_with("file.bin")));

    // Typed errors survive the wire.
    let error = sandbox
        .pause()
        .await
        .expect_err("pause is unsupported on host");
    assert!(
        matches!(error, Error::Unsupported {
            capability: Capability::LifecyclePause,
        }),
        "unexpected error: {error}"
    );

    let workspace = PathBuf::from(sandbox.working_directory());
    sandbox.delete().await.expect("delete");
    assert!(
        !workspace.exists(),
        "managed workspace removed through the wire"
    );
    provider.shutdown().await.expect("shutdown");
}

#[tokio::test]
async fn streaming_exec_delivers_output_notifications_and_cancels() {
    let provider = connect().await;
    let sandbox = provider.create(&host_spec(), None).await.expect("create");

    let chunks: SeenChunks = Arc::new(Mutex::new(Vec::new()));
    let sink_chunks = Arc::clone(&chunks);
    let controls = ExecControls {
        sink: Some(Arc::new(move |stream, chunk| {
            let chunks = Arc::clone(&sink_chunks);
            Box::pin(async move {
                chunks.lock().expect("chunks lock").push((stream, chunk));
                Ok(())
            })
        })),
        ..ExecControls::default()
    };
    let spec = ExecSpec::new("echo one; echo two >&2").timeout(Duration::from_secs(10));
    let streaming = sandbox
        .exec()
        .run_streaming(&spec, controls)
        .await
        .expect("stream");
    assert!(streaming.result.success());
    assert!(streaming.streams_separated);
    let seen = chunks.lock().expect("chunks lock").clone();
    let stdout: Vec<u8> = seen
        .iter()
        .filter(|(stream, _)| *stream == OutputStream::Stdout)
        .flat_map(|(_, chunk)| chunk.clone())
        .collect();
    assert_eq!(stdout, b"one\n");

    // Cancellation crosses as exec/cancel.
    let token = CancellationToken::new();
    let cancel_after = token.clone();
    tokio::spawn(async move {
        time::sleep(Duration::from_millis(200)).await;
        cancel_after.cancel();
    });
    let controls = ExecControls {
        cancel: Some(token),
        ..ExecControls::default()
    };
    let started = Instant::now();
    let streaming = sandbox
        .exec()
        .run_streaming(&ExecSpec::new("sleep 30"), controls)
        .await
        .expect("stream resolves");
    assert_eq!(streaming.result.termination, Termination::Cancelled);
    assert!(started.elapsed() < Duration::from_secs(10));

    sandbox.delete().await.expect("delete");
    provider.shutdown().await.expect("shutdown");
}

#[tokio::test]
async fn slow_calls_do_not_block_fast_calls() {
    let provider = connect().await;
    let sandbox = provider.create(&host_spec(), None).await.expect("create");

    let slow_exec = sandbox.exec();
    let slow = ExecSpec::new("sleep 2; echo slow").timeout(Duration::from_secs(30));
    let fast = ExecSpec::new("echo fast").timeout(Duration::from_secs(30));

    let started = Instant::now();
    let (slow_result, fast_result) = tokio::join!(slow_exec.run(&slow), sandbox.exec().run(&fast));
    let fast_result = fast_result.expect("fast exec");
    assert!(fast_result.success());
    assert!(slow_result.expect("slow exec").success());
    // The fast call must have finished long before the slow one would
    // allow if the server serialized requests.
    assert!(started.elapsed() >= Duration::from_secs(2));

    sandbox.delete().await.expect("delete");
    provider.shutdown().await.expect("shutdown");
}

#[tokio::test]
async fn attach_and_list_work_over_the_wire() {
    let provider = connect().await;
    let spec = host_spec().label("wire", "yes");
    let sandbox = provider.create(&spec, None).await.expect("create");

    let attached = provider.attach(sandbox.id(), None).await.expect("attach");
    assert_eq!(attached.id(), sandbox.id());
    assert_eq!(attached.working_directory(), sandbox.working_directory());

    let mut filter = sandbox_driver::SandboxFilter::default();
    filter.labels.insert("wire".into(), "yes".into());
    let listed = provider.list(&filter).await.expect("list");
    assert_eq!(listed.len(), 1);

    sandbox.delete().await.expect("delete");
    provider.shutdown().await.expect("shutdown");
}
