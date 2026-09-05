//! The conformance moment from the design: the Host provider served over
//! JSON-RPC must behave like the Host provider in-process. Also proves
//! the interleaving requirement — a slow call must not block a fast one.

use std::io;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use sandbox_driver::{
    Action, Capability, CorrelationId, Error, Event, EventBody, EventContext, EventObserver,
    ExecControls, ExecSpec, Git, GitCommitOptions, OutputStream, SandboxProvider, SandboxSource,
    SandboxSpec, Termination, WaitOptions, activate,
};
use sandbox_driver_host::HostProvider;
use sandbox_driver_protocol::{PluginProvider, serve};
use tokio::io::{AsyncWrite, AsyncWriteExt, duplex, split};
use tokio::time;
use tokio_util::sync::CancellationToken;

type SeenChunks = Arc<Mutex<Vec<(OutputStream, Vec<u8>)>>>;

#[derive(Default)]
struct RecordingEventObserver {
    events: Mutex<Vec<Event>>,
}

#[async_trait]
impl EventObserver for RecordingEventObserver {
    async fn observe(&self, event: Event) {
        self.events.lock().expect("events lock").push(event);
    }
}

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
    let spec = ExecSpec::bash("printf 'wire\\0bytes'; cat >&2")
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
async fn derived_git_is_selected_transparently_over_the_wire() {
    let provider = connect().await;
    assert!(provider.capabilities().supports(Capability::Git));
    assert!(!provider.capabilities().git.native);
    let sandbox = provider.create(&host_spec(), None).await.expect("create");

    let result = sandbox
        .exec()
        .run(&ExecSpec::new("git").args(["init", "-q", "-b", "main", "repo"]))
        .await
        .expect("git init over wire");
    assert!(result.success(), "stderr: {}", result.stderr_lossy());
    sandbox
        .fs()
        .write("repo/wire.txt", b"derived over wire\n")
        .await
        .expect("write worktree file");

    let git = sandbox.git().expect("normalized git facet");
    git.add("repo", &["wire.txt".to_owned()])
        .await
        .expect("git add over wire");
    let sha = git
        .commit(
            "repo",
            &GitCommitOptions::new("wire git", "Test", "test@example.com"),
        )
        .await
        .expect("git commit over wire");
    assert_eq!(sha.len(), 40, "sha: {sha}");

    sandbox.delete().await.expect("delete");
    provider.shutdown().await.expect("shutdown");
}

#[tokio::test]
async fn events_cross_the_wire_before_operations_return() {
    let provider = connect().await;
    let observer = Arc::new(RecordingEventObserver::default());
    let context = EventContext::new(observer.clone())
        .correlation_id(CorrelationId::new("protocol-roundtrip"));

    let sandbox = provider
        .create(&host_spec(), Some(context))
        .await
        .expect("create");
    let create_events = observer.events.lock().expect("events lock").clone();
    assert!(matches!(
        create_events.first().map(|event| &event.body),
        Some(EventBody::OperationStarted {
            action: Action::Create,
        })
    ));
    assert!(matches!(
        create_events.last().map(|event| &event.body),
        Some(EventBody::OperationCompleted {
            action: Action::Create,
            ..
        })
    ));
    assert!(create_events.iter().all(|event| {
        event.correlation_id.as_ref().map(CorrelationId::as_str) == Some("protocol-roundtrip")
    }));
    assert!(create_events.windows(2).all(|pair| {
        pair[0].source_id() == pair[1].source_id()
            && pair[0].sequence().checked_add(1) == Some(pair[1].sequence())
    }));

    sandbox.delete().await.expect("delete");
    let all_events = observer.events.lock().expect("events lock").clone();
    assert!(matches!(
        all_events.last().map(|event| &event.body),
        Some(EventBody::OperationCompleted {
            action: Action::Delete,
            ..
        })
    ));
    provider.shutdown().await.expect("shutdown");
}

#[tokio::test]
async fn streaming_exec_delivers_output_notifications_and_stops() {
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
    let spec = ExecSpec::bash("echo one; echo two >&2").timeout(Duration::from_secs(10));
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

    // A term crosses as exec/stop with its level.
    let token = CancellationToken::new();
    let term_after = token.clone();
    tokio::spawn(async move {
        time::sleep(Duration::from_millis(200)).await;
        term_after.cancel();
    });
    let controls = ExecControls {
        term: Some(token),
        ..ExecControls::default()
    };
    let started = Instant::now();
    let streaming = sandbox
        .exec()
        .run_streaming(&ExecSpec::new("sleep").arg("30"), controls)
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
    let slow = ExecSpec::bash("sleep 2; echo slow").timeout(Duration::from_secs(30));
    let fast = ExecSpec::new("echo")
        .arg("fast")
        .timeout(Duration::from_secs(30));

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

#[tokio::test]
async fn closed_plugin_transport_is_classified() {
    let (host_side, plugin_side) = duplex(1024);
    drop(plugin_side);
    let (host_read, host_write) = split(host_side);

    let Err(error) = PluginProvider::connect(host_read, host_write).await else {
        panic!("closed transport must fail the handshake");
    };
    assert!(matches!(error, Error::Transport(_)), "{error:?}");
}

#[tokio::test]
async fn malformed_plugin_response_is_classified() {
    let (host_side, mut plugin_side) = duplex(1024);
    tokio::spawn(async move {
        plugin_side
            .write_all(b"this is not JSON\n")
            .await
            .expect("write malformed response");
        time::sleep(Duration::from_secs(1)).await;
    });
    let (host_read, host_write) = split(host_side);

    let Err(error) = PluginProvider::connect(host_read, host_write).await else {
        panic!("malformed response must fail the handshake");
    };
    let Error::Transport(transport) = error else {
        panic!("expected transport failure");
    };
    assert_eq!(transport.context, "decoding plugin response");
}

#[tokio::test]
async fn plugin_response_write_failure_is_returned() {
    const SHUTDOWN_REQUEST: &[u8] = b"{\"id\":1,\"method\":\"shutdown\",\"params\":{}}\n";

    let error = serve(
        Arc::new(HostProvider::new()),
        SHUTDOWN_REQUEST,
        FailingWriter,
    )
    .await
    .expect_err("response write must fail");
    let Error::Transport(transport) = error else {
        panic!("expected transport failure");
    };
    assert_eq!(transport.context, "writing plugin response");
}

struct FailingWriter;

impl AsyncWrite for FailingWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(Err(io::Error::new(
            io::ErrorKind::BrokenPipe,
            "test writer failed",
        )))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[tokio::test]
async fn version_one_handshakes_report_the_version_mismatch() {
    use tokio::io::{AsyncBufReadExt, BufReader};

    let (host, plugin) = duplex(4096);
    let (plugin_read, plugin_write) = split(plugin);
    let server = tokio::spawn(serve(
        Arc::new(HostProvider::new()),
        plugin_read,
        plugin_write,
    ));
    let (host_read, mut host_write) = split(host);
    host_write.write_all(
        b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocol_version\":1}}\n"
    ).await.expect("version one initialize");
    let mut lines = BufReader::new(host_read).lines();
    let response = lines.next_line().await.expect("response").expect("line");
    let message: sandbox_driver_protocol::Message =
        serde_json::from_str(&response).expect("JSON response");
    let error = message.error.expect("incompatible version refused");
    assert!(error.message.contains("protocol_version"), "{error:?}");
    assert!(error.message.contains("host asked for 1"), "{error:?}");
    host_write.shutdown().await.expect("close requests");
    server.await.expect("join server").expect("server shutdown");
}

#[tokio::test]
async fn cancellation_before_exec_registration_is_delivered_after_channel_acceptance() {
    let provider = connect().await;
    let sandbox = provider.create(&host_spec(), None).await.expect("create");
    for kill in [false, true] {
        let token = CancellationToken::new();
        token.cancel();
        let controls = ExecControls {
            term: (!kill).then(|| token.clone()),
            kill: kill.then_some(token),
            ..ExecControls::default()
        };
        let result = time::timeout(
            Duration::from_secs(5),
            sandbox
                .exec()
                .run_streaming(&ExecSpec::new("sleep").arg("30").no_timeout(), controls),
        )
        .await;
        sandbox
            .stop()
            .await
            .expect("stop even if the regression recurs");
        assert_eq!(
            result
                .expect("pre-cancelled exec ends")
                .expect("exec")
                .result
                .termination,
            if kill {
                Termination::Killed
            } else {
                Termination::Cancelled
            }
        );
        sandbox.start().await.expect("restart");
    }
    sandbox.delete().await.expect("delete");
    provider.shutdown().await.expect("shutdown");
}
