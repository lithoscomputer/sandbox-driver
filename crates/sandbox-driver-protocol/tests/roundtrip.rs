//! The conformance moment from the design: the Host provider served over
//! JSON-RPC must behave like the Host provider in-process. Also proves
//! the interleaving requirement — a slow call must not block a fast one.

use std::path::PathBuf;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use std::{future, io, mem, process};

use async_trait::async_trait;
use sandbox_driver::{
    Action, Capabilities, Capability, CorrelationId, Error, Event, EventBody, EventContext,
    EventEmitter, EventObserver, EventSubject, ExecControls, ExecSpec, Git, GitCommitOptions,
    OutputStream, ProviderKind, Result, Sandbox, SandboxFilter, SandboxId, SandboxProvider,
    SandboxSource, SandboxSpec, SandboxStatus, SpawnSpec, StdinSource, Termination, WaitOptions,
    activate,
};
use sandbox_driver_host::HostProvider;
use sandbox_driver_protocol::channel::TrustedPeer;
use sandbox_driver_protocol::{PluginProvider, serve};
use tokio::io::{
    AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufWriter, ReadBuf, copy, duplex, repeat,
    split,
};
use tokio::sync::Notify;
use tokio::{fs, task, time};
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
async fn shutdown_cancels_an_active_exec_before_the_server_returns() {
    let host = Arc::new(HostProvider::new());
    let local = host
        .create(&host_spec(), None)
        .await
        .expect("local sandbox");
    let (host_side, plugin_side) = duplex(4096);
    let (host_read, host_write) = split(host_side);
    let (plugin_read, plugin_write) = split(plugin_side);
    let server = tokio::spawn(serve(host, plugin_read, plugin_write));
    let provider = PluginProvider::connect(host_read, host_write)
        .await
        .expect("handshake");
    let sandbox = provider.attach(local.id(), None).await.expect("attach");
    let started = Arc::new(Notify::new());
    let ready = Arc::clone(&started);
    let exec = tokio::spawn(async move {
        sandbox
            .exec()
            .run_streaming(
                &ExecSpec::bash("echo ready; exec sleep 300").no_timeout(),
                ExecControls {
                    sink: Some(Arc::new(move |_, _| {
                        ready.notify_one();
                        Box::pin(async { Ok(()) })
                    })),
                    ..ExecControls::buffered()
                },
            )
            .await
    });
    let outcome = time::timeout(Duration::from_secs(5), async {
        started.notified().await;
        provider.shutdown().await.expect("shutdown");
        let result = exec.await.expect("join exec").expect("exec result");
        server.await.expect("join server").expect("server shutdown");
        result.result.termination
    })
    .await;
    local.delete().await.expect("clean up local sandbox");
    assert_eq!(
        outcome.expect("shutdown ends the active exec and server"),
        Termination::Killed
    );
}

#[tokio::test]
async fn shutdown_cancels_an_exec_queued_before_registration() {
    use sandbox_driver_protocol::channel::ChannelListener;
    use sandbox_driver_protocol::{Message, methods as m};
    use tokio::io::{AsyncBufReadExt, BufReader};

    let host = Arc::new(HostProvider::new());
    let sandbox = host.create(&host_spec(), None).await.expect("sandbox");
    let listener = ChannelListener::bind().expect("data listener");
    let (host_side, plugin_side) = duplex(16384);
    let (host_read, mut host_write) = split(host_side);
    let (plugin_read, plugin_write) = split(plugin_side);
    let mut server = tokio::spawn(serve(host, plugin_read, plugin_write));
    let initialize = Message::request(
        1,
        m::INITIALIZE,
        serde_json::to_value(m::InitializeParams {
            protocol_version: 2,
            data_transport:   listener.transport(),
        })
        .unwrap(),
    );
    host_write
        .write_all(format!("{}\n", serde_json::to_string(&initialize).unwrap()).as_bytes())
        .await
        .unwrap();
    let mut responses = BufReader::new(host_read).lines();
    let initialized: Message =
        serde_json::from_str(&responses.next_line().await.unwrap().unwrap()).unwrap();
    assert!(initialized.error.is_none());

    let (channel, receiver) = listener.expect().expect("admitted");
    let exec = Message::request(
        2,
        m::EXEC_STREAM,
        serde_json::to_value(m::ExecStreamParams {
            sandbox_id: sandbox.id().as_str().to_owned(),
            exec_id: "queued-exec".to_owned(),
            channel,
            spec: m::ExecSpecDto::from_spec(&ExecSpec::new("sleep").arg("300").no_timeout()),
            stdin: false,
            retained_output_limit: Some(0),
        })
        .unwrap(),
    );
    let shutdown = Message::request(3, m::SHUTDOWN, serde_json::Value::Null);
    // Both lines arrive in one write on this current-thread runtime. The
    // server reads shutdown before the spawned exec task can register.
    host_write
        .write_all(
            format!(
                "{}\n{}\n",
                serde_json::to_string(&exec).unwrap(),
                serde_json::to_string(&shutdown).unwrap()
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let outcome = time::timeout(Duration::from_secs(3), async {
        let _channel = receiver.accept().await.expect("exec data channel");
        let mut termination = None;
        while let Some(line) = responses.next_line().await.unwrap() {
            let response: Message = serde_json::from_str(&line).unwrap();
            if response.id == Some(2) {
                let result: m::ExecStreamResult =
                    serde_json::from_value(response.result.expect("exec result")).unwrap();
                termination = Some(result.result.termination);
            }
        }
        (&mut server).await.unwrap().unwrap();
        termination
    })
    .await;
    sandbox
        .delete()
        .await
        .expect("cleanup even if shutdown fails");
    if outcome.is_err() {
        server.abort();
    }
    assert_eq!(
        outcome.expect("queued exec cannot keep shutdown alive"),
        Some(Termination::Killed)
    );
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

    // Binary filesystem content crosses the data channel.
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
async fn file_transfers_make_progress_before_input_finishes() {
    const LENGTH: u64 = 8 * 1024 * 1024 + 17;
    const BYTE: u8 = 0xa5;
    let provider = connect().await;
    let sandbox = provider.create(&host_spec(), None).await.expect("create");
    let (mut input, mut producer) = duplex(64 * 1024);
    let path = PathBuf::from(sandbox.working_directory()).join("nested/large.bin");
    let produce = async {
        copy(&mut repeat(BYTE).take(64 * 1024), &mut producer)
            .await
            .expect("first chunk");
        // The server must write before the source reaches EOF. A server
        // that collects the full channel cannot pass this handshake.
        time::timeout(Duration::from_secs(10), async {
            loop {
                if fs::metadata(&path)
                    .await
                    .is_ok_and(|metadata| metadata.len() > 0)
                {
                    break;
                }
                time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("file grows while the source remains open");
        copy(&mut repeat(BYTE).take(LENGTH - 64 * 1024), &mut producer)
            .await
            .expect("remaining chunks");
        // No shutdown: the receiver must stop at the declared length.
    };
    let transfer = sandbox
        .fs()
        .write_from("nested/large.bin", &mut input, LENGTH);
    let (result, ()) = time::timeout(Duration::from_secs(20), async {
        tokio::join!(transfer, produce)
    })
    .await
    .expect("streaming write completes");
    result.expect("write file");

    let mut output = BufWriter::with_capacity(32 * 1024, ByteSink::new(BYTE));
    sandbox
        .fs()
        .read_to("nested/large.bin", &mut output)
        .await
        .expect("read file");
    assert_eq!(
        output.get_ref().written,
        LENGTH,
        "read_to flushes the final partial buffer"
    );

    let downloaded = PathBuf::from(sandbox.working_directory()).join("local/nested/download.bin");
    sandbox
        .fs()
        .download("nested/large.bin", &downloaded)
        .await
        .expect("download");
    sandbox
        .fs()
        .upload(&downloaded, "uploaded.bin")
        .await
        .expect("upload");
    let mut uploaded = ByteSink::new(BYTE);
    sandbox
        .fs()
        .read_to("uploaded.bin", &mut uploaded)
        .await
        .expect("read uploaded file");
    assert_eq!(uploaded.written, LENGTH);
    sandbox.delete().await.expect("delete");
    provider.shutdown().await.expect("shutdown");
}

#[tokio::test]
async fn file_transfer_failures_return_without_hanging() {
    let provider = connect().await;
    let sandbox = provider.create(&host_spec(), None).await.expect("create");
    let error = time::timeout(
        Duration::from_secs(5),
        sandbox
            .fs()
            .write_from("short.bin", &mut b"short".as_slice(), 1024 * 1024),
    )
    .await
    .expect("short source terminates transfer")
    .expect_err("short source fails");
    assert!(
        matches!(error, Error::Io { source, .. } if source.kind() == io::ErrorKind::UnexpectedEof)
    );

    sandbox
        .fs()
        .write_from("large.bin", &mut repeat(0), 8 * 1024 * 1024)
        .await
        .expect("large file");
    let error = time::timeout(
        Duration::from_secs(5),
        sandbox.fs().read_to("large.bin", &mut FailingWriter),
    )
    .await
    .expect("failed sink terminates transfer")
    .expect_err("failed sink fails");
    assert!(
        matches!(error, Error::Io { source, .. } if source.kind() == io::ErrorKind::BrokenPipe)
    );

    sandbox
        .fs()
        .write("small.bin", b"buffered")
        .await
        .expect("small file");
    let mut buffered_failure = BufWriter::with_capacity(1024, FailingWriter);
    let error = sandbox
        .fs()
        .read_to("small.bin", &mut buffered_failure)
        .await
        .expect_err("flush failure propagates");
    assert!(
        matches!(error, Error::Io { source, .. } if source.kind() == io::ErrorKind::BrokenPipe)
    );
    sandbox.delete().await.expect("delete");
    provider.shutdown().await.expect("shutdown");
}

struct ByteSink {
    byte:    u8,
    written: u64,
}

impl ByteSink {
    fn new(byte: u8) -> Self {
        Self { byte, written: 0 }
    }
}

impl AsyncWrite for ByteSink {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        assert!(
            buffer.iter().all(|byte| *byte == self.byte),
            "file content preserved"
        );
        self.written += buffer.len() as u64;
        Poll::Ready(Ok(buffer.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        panic!("read_to must leave its output open");
    }
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
        ..ExecControls::buffered()
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
        ..ExecControls::buffered()
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
async fn preview_urls_reach_the_host_sandbox_and_release_is_idempotent() {
    let provider = connect().await;
    let sandbox = provider.create(&host_spec(), None).await.expect("create");
    assert!(sandbox.capabilities().access.preview_urls);
    let preview = sandbox.preview_urls().expect("declared facet");
    let url = preview.preview_url(8080).await.expect("preview url");
    assert_eq!(url.url, "http://127.0.0.1:8080");
    assert!(url.headers.is_empty());
    preview.release_preview_url(8080).await.expect("release");
    preview
        .release_preview_url(8080)
        .await
        .expect("a second release succeeds");
    preview
        .release_preview_url(9)
        .await
        .expect("releasing a port never requested succeeds");
    sandbox.delete().await.expect("delete");
    provider.shutdown().await.expect("shutdown");
}

/// Output crosses the wire as bytes: a last line without its newline
/// arrives without one, and nothing is added or reframed on the way.
#[tokio::test]
async fn exec_output_is_byte_exact_without_a_trailing_newline() {
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
        retained_output_limit: Some(64),
        ..ExecControls::buffered()
    };
    let spec = ExecSpec::new("printf")
        .args(["a\\nb"])
        .timeout(Duration::from_secs(10));
    let streaming = sandbox
        .exec()
        .run_streaming(&spec, controls)
        .await
        .expect("stream");
    assert!(streaming.result.success());
    let stdout: Vec<u8> = chunks
        .lock()
        .expect("chunks lock")
        .iter()
        .filter(|(stream, _)| *stream == OutputStream::Stdout)
        .flat_map(|(_, chunk)| chunk.clone())
        .collect();
    assert_eq!(stdout, b"a\nb");
    assert_eq!(streaming.result.stdout, b"a\nb");
    let buffered = sandbox
        .exec()
        .run(&ExecSpec::new("printf").args(["a\\nb"]))
        .await
        .expect("buffered run");
    assert_eq!(buffered.stdout, b"a\nb");
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

    let mut filter = SandboxFilter::default();
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
    const SHUTDOWN_REQUEST: &[u8] =
        b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"shutdown\",\"params\":{}}\n";

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

#[tokio::test]
async fn shutdown_response_is_flushed_before_the_server_returns() {
    let delivered = Arc::new(Mutex::new(Vec::new()));
    let writer = FlushWriter {
        buffered:  Vec::new(),
        delivered: delivered.clone(),
    };
    serve(
        Arc::new(HostProvider::new()),
        b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"shutdown\",\"params\":{}}\n".as_slice(),
        writer,
    )
    .await
    .expect("server shutdown");
    let response: sandbox_driver_protocol::Message =
        serde_json::from_slice(&delivered.lock().expect("delivered bytes"))
            .expect("the shutdown reply reached the client");
    assert_eq!(response.id, Some(1));
    assert!(response.error.is_none());
}

/// Like Tokio stdout, shutdown alone does not finish a pending write.
struct FlushWriter {
    buffered:  Vec<u8>,
    delivered: Arc<Mutex<Vec<u8>>>,
}

impl AsyncWrite for FlushWriter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.buffered.extend_from_slice(bytes);
        Poll::Ready(Ok(bytes.len()))
    }

    fn poll_flush(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        let bytes = mem::take(&mut self.buffered);
        self.delivered
            .lock()
            .expect("delivered bytes")
            .extend(bytes);
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
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
            ..ExecControls::buffered()
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

async fn connect_limited(limits: sandbox_driver_protocol::TransportLimits) -> PluginProvider {
    connect_separate_limits(limits.clone(), limits).await
}

async fn connect_separate_limits(
    client_limits: sandbox_driver_protocol::TransportLimits,
    server_limits: sandbox_driver_protocol::TransportLimits,
) -> PluginProvider {
    let (host, plugin) = duplex(1024 * 1024);
    let (read, write) = split(host);
    let (plugin_read, plugin_write) = split(plugin);
    tokio::spawn(sandbox_driver_protocol::serve_with_limits(
        Arc::new(HostProvider::new()),
        plugin_read,
        plugin_write,
        server_limits,
    ));
    PluginProvider::connect_with_limits(
        read,
        write,
        client_limits,
        TrustedPeer::Process(process::id()),
    )
    .await
    .expect("limited connection")
}

#[tokio::test]
async fn streaming_defaults_to_no_copy_and_buffered_files_enforce_the_limit() {
    let mut limits = sandbox_driver_protocol::TransportLimits::default();
    limits.buffered_value_bytes = 4;
    let provider = connect_limited(limits).await;
    let sandbox = provider.create(&host_spec(), None).await.expect("sandbox");
    let result = sandbox
        .exec()
        .run_streaming(&ExecSpec::bash("printf hello"), ExecControls::default())
        .await
        .expect("stream");
    assert!(result.result.stdout.is_empty());
    assert_eq!(result.stdout_capture.observed_bytes, 5);
    assert_eq!(result.stdout_capture.omitted_bytes, 5);
    assert!(!result.stdout_capture.truncated);
    sandbox.fs().write("large", b"hello").await.expect("write");
    assert!(matches!(
        sandbox.fs().read("large").await,
        Err(Error::LimitExceeded { max_bytes: 4, .. })
    ));
    let mut output = Vec::new();
    sandbox
        .fs()
        .read_to("large", &mut output)
        .await
        .expect("stream file");
    assert_eq!(output, b"hello");
    sandbox.delete().await.expect("delete");
    provider.shutdown().await.expect("shutdown");
}

#[tokio::test]
async fn io_overload_rejects_before_command_effects_and_reserved_controls_work() {
    assert_io_overload(true).await;
}

#[tokio::test]
async fn server_rejects_ten_thousand_excess_operations_before_effects() {
    assert_io_overload(false).await;
}

async fn assert_io_overload(client_limited: bool) {
    let mut limits = sandbox_driver_protocol::TransportLimits::default();
    limits.active_io = 1;
    let client_limits = if client_limited {
        limits.clone()
    } else {
        sandbox_driver_protocol::TransportLimits::default()
    };
    let provider = connect_separate_limits(client_limits, limits).await;
    let sandbox = provider.create(&host_spec(), None).await.expect("sandbox");
    let active = Arc::clone(&sandbox);
    let ready = Arc::new(Notify::new());
    let started = Arc::clone(&ready);
    let kill = CancellationToken::new();
    let token = kill.clone();
    let task = tokio::spawn(async move {
        active
            .exec()
            .run_streaming(
                &ExecSpec::bash("echo ready; exec sleep 300"),
                ExecControls {
                    kill: Some(token),
                    sink: Some(Arc::new(move |_, _| {
                        started.notify_one();
                        Box::pin(async { Ok(()) })
                    })),
                    ..ExecControls::default()
                },
            )
            .await
    });
    time::timeout(Duration::from_secs(5), ready.notified())
        .await
        .expect("active command");
    for _ in 0..10_000 {
        let error = sandbox
            .exec()
            .run(&ExecSpec::bash("touch should-not-exist"))
            .await
            .expect_err("rejected");
        assert!(matches!(error, Error::Overloaded { limit } if limit == "active_io"));
    }
    time::timeout(Duration::from_secs(1), provider.health())
        .await
        .expect("reserved health")
        .expect("healthy");
    kill.cancel();
    let result = time::timeout(Duration::from_secs(5), task)
        .await
        .expect("stop available")
        .expect("task")
        .expect("kill result");
    assert_eq!(result.result.termination, Termination::Killed);
    assert!(!sandbox.fs().exists("should-not-exist").await.expect("stat"));
    assert!(
        sandbox
            .exec()
            .run(&ExecSpec::new("true"))
            .await
            .expect("resumed")
            .success()
    );
    sandbox.delete().await.expect("delete");
    provider.shutdown().await.expect("shutdown");
}

struct BlockedObserver;
#[async_trait]
impl EventObserver for BlockedObserver {
    async fn observe(&self, _: Event) {
        future::pending::<()>().await;
    }
}

#[tokio::test]
async fn blocked_observer_does_not_block_responses_and_reports_subscription_failure() {
    let mut limits = sandbox_driver_protocol::TransportLimits::default();
    limits.output_progress_timeout = Duration::from_millis(50);
    let provider = connect_limited(limits).await;
    let sandbox = time::timeout(
        Duration::from_secs(2),
        provider.create(
            &host_spec(),
            Some(EventContext::new(Arc::new(BlockedObserver))),
        ),
    )
    .await
    .expect("observer does not block create")
    .expect("sandbox");
    time::timeout(Duration::from_secs(2), async {
        while provider.event_delivery_error().is_none() {
            task::yield_now().await;
        }
    })
    .await
    .expect("explicit observer failure");
    provider.health().await.expect("healthy control transport");
    sandbox.delete().await.expect("delete");
    provider.shutdown().await.expect("shutdown");
}

#[tokio::test]
async fn blocked_output_cancels_but_a_quiet_command_has_no_progress_deadline() {
    let mut limits = sandbox_driver_protocol::TransportLimits::default();
    limits.output_progress_timeout = Duration::from_millis(50);
    limits.hard_cancel_drain_timeout = Duration::from_millis(100);
    let provider = connect_limited(limits).await;
    let sandbox = provider.create(&host_spec(), None).await.expect("sandbox");
    let quiet = sandbox
        .exec()
        .run(&ExecSpec::bash("sleep 0.2"))
        .await
        .expect("quiet command");
    assert!(quiet.success());
    let outcome = time::timeout(
        Duration::from_secs(2),
        sandbox.exec().run_streaming(
            &ExecSpec::bash("echo ready; exec sleep 300"),
            ExecControls {
                sink: Some(Arc::new(|_, _| Box::pin(future::pending()))),
                ..ExecControls::default()
            },
        ),
    )
    .await
    .expect("blocked output waiting is bounded");
    match outcome {
        Ok(result) => assert!(!result.result.success()),
        Err(error) => assert!(matches!(error, Error::Transport(_) | Error::Incomplete(_))),
    }
    assert!(
        sandbox
            .exec()
            .run(&ExecSpec::new("true"))
            .await
            .expect("unrelated channel")
            .success()
    );
    sandbox.delete().await.expect("delete");
    provider.shutdown().await.expect("shutdown");
}

struct FailedInput;
impl AsyncRead for FailedInput {
    fn poll_read(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        _: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Ready(Err(io::Error::other("source failed")))
    }
}

#[tokio::test]
async fn failed_input_cannot_be_reported_as_complete() {
    let provider = connect().await;
    let sandbox = provider.create(&host_spec(), None).await.expect("sandbox");
    let result = time::timeout(
        Duration::from_secs(5),
        sandbox
            .exec()
            .run_streaming(&ExecSpec::bash("cat >/dev/null"), ExecControls {
                stdin: Some(StdinSource::new(FailedInput)),
                ..ExecControls::default()
            }),
    )
    .await
    .expect("failed input ends local waiting");
    assert!(
        result.is_err(),
        "source failure must not become a successful EOF"
    );
    provider
        .health()
        .await
        .expect("unrelated controls remain usable");
    sandbox.delete().await.expect("delete");
    provider.shutdown().await.expect("shutdown");
}

struct FloodProvider {
    host:    HostProvider,
    notices: usize,
}

#[async_trait]
impl SandboxProvider for FloodProvider {
    fn kind(&self) -> &ProviderKind {
        self.host.kind()
    }
    fn capabilities(&self) -> &Capabilities {
        self.host.capabilities()
    }
    async fn create(
        &self,
        spec: &SandboxSpec,
        events: Option<EventContext>,
    ) -> Result<Arc<dyn Sandbox>> {
        let emitter = EventEmitter::new(self.kind().clone(), events.clone());
        for _ in 0..self.notices {
            emitter
                .notice(EventSubject::pending_sandbox(None), "flood", "notice")
                .await;
        }
        self.host.create(spec, events).await
    }
    async fn attach(
        &self,
        id: &SandboxId,
        events: Option<EventContext>,
    ) -> Result<Arc<dyn Sandbox>> {
        self.host.attach(id, events).await
    }
    async fn list(&self, filter: &SandboxFilter) -> Result<Vec<SandboxStatus>> {
        self.host.list(filter).await
    }
}

#[tokio::test]
async fn event_flood_reports_failure_and_keeps_control_responses_available() {
    for server_limited in [false, true] {
        let mut client_limits = sandbox_driver_protocol::TransportLimits::default();
        let mut server_limits = client_limits.clone();
        if server_limited {
            server_limits.event_queue_messages = 2;
        } else {
            client_limits.event_queue_messages = 2;
        }
        let (host, plugin) = duplex(4096);
        let (read, write) = split(host);
        let (plugin_read, plugin_write) = split(plugin);
        let server = task::spawn(sandbox_driver_protocol::serve_with_limits(
            Arc::new(FloodProvider {
                host:    HostProvider::new(),
                notices: 10000,
            }),
            plugin_read,
            plugin_write,
            server_limits,
        ));
        let provider = PluginProvider::connect_with_limits(
            read,
            write,
            client_limits,
            TrustedPeer::Process(process::id()),
        )
        .await
        .expect("connect");
        let sandbox = time::timeout(
            Duration::from_secs(5),
            provider.create(
                &host_spec(),
                Some(EventContext::new(Arc::new(BlockedObserver))),
            ),
        )
        .await
        .expect("flood does not stall response")
        .expect("sandbox");
        time::timeout(Duration::from_secs(1), async {
            while provider.event_delivery_error().is_none() {
                task::yield_now().await;
            }
        })
        .await
        .expect("explicit subscription failure");
        time::timeout(
            Duration::from_secs(1),
            provider.list(&SandboxFilter::default()),
        )
        .await
        .expect("control available after flood")
        .expect("list");
        assert!(!provider.is_closed());
        sandbox.delete().await.expect("delete");
        provider.shutdown().await.expect("shutdown");
        server.await.expect("join server").expect("server result");
    }
}

#[tokio::test]
async fn stdio_wait_and_dropped_handles_return_admission_and_owned_tasks() {
    let mut limits = sandbox_driver_protocol::TransportLimits::default();
    limits.active_io = 1;
    let provider = connect_limited(limits).await;
    let sandbox = provider.create(&host_spec(), None).await.expect("sandbox");
    for _ in 0..50 {
        let mut process = sandbox
            .exec()
            .spawn_stdio(&SpawnSpec::new("cat"))
            .await
            .expect("stdio");
        process.stdin.write_all(b"hello\n").await.expect("input");
        process.stdin.shutdown().await.expect("EOF");
        let mut output = Vec::new();
        time::timeout(
            Duration::from_secs(3),
            process.stdout.read_to_end(&mut output),
        )
        .await
        .expect("output deadline")
        .expect("output");
        assert_eq!(output, b"hello\n");
        let (termination, code) = time::timeout(Duration::from_secs(3), process.handle.wait())
            .await
            .expect("wait deadline");
        assert_eq!((termination, code), (Termination::Exited, Some(0)));
        // Keep the completed handle alive while reusing its released admission.
        sandbox
            .exec()
            .run(&ExecSpec::new("true"))
            .await
            .expect("admission after wait");
        drop(process);
        let process = sandbox
            .exec()
            .spawn_stdio(&SpawnSpec::new("cat"))
            .await
            .expect("second stdio");
        drop(process);
        time::timeout(Duration::from_secs(5), async {
            loop {
                let stats = provider.transport_diagnostics().await.expect("diagnostics");
                if stats.client.active_io == 0
                    && stats.client.cleanup_tasks == 0
                    && stats.server.active_io == 0
                    && stats.server.stdios == 0
                    && stats.server.background_tasks == 0
                {
                    break;
                }
                assert_eq!(stats.client.failed_cleanups, 0);
                time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("dropped stdio is cleaned up");
    }
    sandbox.delete().await.expect("delete");
    provider.shutdown().await.expect("shutdown");
}

#[tokio::test]
async fn cancellation_during_streamed_input_drops_the_source_and_preserves_other_channels() {
    let provider = connect().await;
    let sandbox = provider.create(&host_spec(), None).await.expect("sandbox");
    let (mut source, stdin) = duplex(64);
    let kill = CancellationToken::new();
    let token = kill.clone();
    let running = Arc::clone(&sandbox);
    let ready = Arc::new(Notify::new());
    let sent = Arc::clone(&ready);
    let task = task::spawn(async move {
        running
            .exec()
            .run_streaming(
                // Readiness can arrive while the shell is still spawning cat.
                // Cancellation must also kill children created during the stop.
                &ExecSpec::bash("echo ready; cat >/dev/null"),
                ExecControls {
                    stdin: Some(StdinSource::new(stdin)),
                    kill: Some(token),
                    sink: Some(Arc::new(move |_, _| {
                        sent.notify_one();
                        Box::pin(async { Ok(()) })
                    })),
                    ..ExecControls::default()
                },
            )
            .await
    });
    time::timeout(Duration::from_secs(3), ready.notified())
        .await
        .expect("command running");
    source
        .write_all(b"partial input")
        .await
        .expect("input before kill");
    kill.cancel();
    let result = time::timeout(Duration::from_secs(5), task)
        .await
        .expect("drain deadline")
        .expect("join")
        .expect("outcome");
    assert_eq!(result.result.termination, Termination::Killed);
    assert!(
        time::timeout(Duration::from_secs(1), source.write_all(&[0; 128]))
            .await
            .expect("input pump closes")
            .is_err(),
        "the local input pump must be dropped"
    );
    assert!(
        sandbox
            .exec()
            .run(&ExecSpec::new("true"))
            .await
            .expect("unrelated operation")
            .success()
    );
    sandbox.delete().await.expect("delete");
    provider.shutdown().await.expect("shutdown");
}
