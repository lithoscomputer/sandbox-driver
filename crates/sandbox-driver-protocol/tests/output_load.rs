//! Exec output through the wire is lossless and ordered while the machine is
//! busy. Petri's reproducer: a command printing 20,000 lines under the load
//! of a full test suite must deliver every line, in order, to the caller's
//! sink, with no `truncated` flag.

use std::hint::black_box;
use std::num::NonZero;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use sandbox_driver::{
    ExecControls, ExecSpec, OutputStream, SandboxProvider, SandboxSource, SandboxSpec,
};
use sandbox_driver_host::HostProvider;
use sandbox_driver_protocol::{PluginProvider, serve};
use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex, split};
use tokio::sync::Mutex as AsyncMutex;
use tokio::task::{JoinSet, yield_now};
use tokio::time;

const LINES: usize = 20_000;

/// Threads spinning on every core, so the plugin's tasks and the host's
/// tasks compete for the machine the way a full test suite makes them.
struct Load {
    stop:    Arc<AtomicBool>,
    threads: Vec<thread::JoinHandle<()>>,
}

impl Load {
    fn start() -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let count = thread::available_parallelism().map_or(4, NonZero::get) * 2;
        let threads = (0..count)
            .map(|_| {
                let stop = Arc::clone(&stop);
                thread::spawn(move || {
                    let mut value = 0_u64;
                    while !stop.load(Ordering::Relaxed) {
                        for i in 0..10_000_u64 {
                            value = black_box(value.wrapping_mul(31).wrapping_add(i));
                        }
                    }
                })
            })
            .collect();
        Self { stop, threads }
    }
}

impl Drop for Load {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        for thread in self.threads.drain(..) {
            let _ = thread.join();
        }
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

fn expected() -> Vec<u8> {
    let mut lines = String::new();
    for n in 1..=LINES {
        lines.push_str(&n.to_string());
        lines.push('\n');
    }
    lines.into_bytes()
}

/// Runs `seq 1 20000` with a sink shaped like Petri's: each chunk is written
/// into a 64 KiB pipe whose reader yields and stalls between reads.
async fn stream_lines(sandbox: &Arc<dyn sandbox_driver::Sandbox>) -> (Vec<u8>, bool) {
    let (writer, mut reader) = duplex(64 * 1024);
    let collected = Arc::new(Mutex::new(Vec::new()));
    let sink_collected = Arc::clone(&collected);
    let reader_task = tokio::spawn(async move {
        let mut buffer = vec![0_u8; 4096];
        let mut reads = 0_u32;
        loop {
            let read = reader.read(&mut buffer).await.expect("pipe read");
            if read == 0 {
                break;
            }
            sink_collected
                .lock()
                .expect("collected lock")
                .extend_from_slice(&buffer[..read]);
            reads += 1;
            if reads % 8 == 0 {
                time::sleep(Duration::from_millis(1)).await;
            } else {
                yield_now().await;
            }
        }
    });
    let writer = Arc::new(AsyncMutex::new(Some(writer)));
    let sink_writer = Arc::clone(&writer);
    let controls = ExecControls {
        sink: Some(Arc::new(move |stream, chunk| {
            let writer = Arc::clone(&sink_writer);
            Box::pin(async move {
                if stream == OutputStream::Stdout {
                    let mut guard = writer.lock().await;
                    let writer = guard.as_mut().expect("writer open while streaming");
                    writer
                        .write_all(&chunk)
                        .await
                        .map_err(|error| sandbox_driver::Error::io("sink write", error))?;
                }
                Ok(())
            })
        })),
        retained_output_limit: Some(0),
        ..ExecControls::buffered()
    };
    let spec = ExecSpec::new("seq")
        .args(["1", &LINES.to_string()])
        .timeout(Duration::from_secs(120));
    let streaming = sandbox
        .exec()
        .run_streaming(&spec, controls)
        .await
        .expect("stream");
    assert!(streaming.result.success(), "{:?}", streaming.result);
    if let Some(mut writer) = writer.lock().await.take() {
        writer.shutdown().await.expect("pipe close");
    }
    reader_task.await.expect("reader task");
    let bytes = collected.lock().expect("collected lock").clone();
    (bytes, streaming.stdout_capture.truncated)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn twenty_thousand_lines_arrive_in_order_under_load() {
    let _load = Load::start();
    let provider = Arc::new(connect().await);
    let sandbox = provider
        .create(&SandboxSpec::new(SandboxSource::HostDirectory), None)
        .await
        .expect("create");

    // Neighbours on the same plugin connection, each streaming its own
    // output through its own channel while the measured command runs.
    let mut neighbours = JoinSet::new();
    for _ in 0..4 {
        let provider = Arc::clone(&provider);
        neighbours.spawn(async move {
            let sandbox = provider
                .create(&SandboxSpec::new(SandboxSource::HostDirectory), None)
                .await
                .expect("create neighbour");
            for _ in 0..3 {
                let (bytes, truncated) = stream_lines(&sandbox).await;
                assert!(!truncated);
                assert_eq!(bytes.len(), expected().len());
            }
            sandbox.delete().await.expect("delete neighbour");
        });
    }

    let started = Instant::now();
    for round in 0..3 {
        let (bytes, truncated) = stream_lines(&sandbox).await;
        assert!(!truncated, "round {round}: the plugin reported truncation");
        let lines = bytes.split(|byte| *byte == b'\n').count().saturating_sub(1);
        assert_eq!(
            lines, LINES,
            "round {round}: {lines} of {LINES} lines arrived"
        );
        assert_eq!(
            bytes,
            expected(),
            "round {round}: lines arrived out of order or altered"
        );
    }
    while let Some(outcome) = neighbours.join_next().await {
        outcome.expect("neighbour task");
    }
    assert!(started.elapsed() < Duration::from_secs(600));

    sandbox.delete().await.expect("delete");
    provider.shutdown().await.expect("shutdown");
}
