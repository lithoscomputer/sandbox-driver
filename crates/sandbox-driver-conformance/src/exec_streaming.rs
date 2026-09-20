//! Streaming exec: streamed stdin, live sinks, ordering under load,
//! partial last lines, retention accounting, and concurrent streams.

use std::io::Cursor;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use sandbox_driver::{Capability, ExecControls, ExecSpec, OutputStream, StdinSource};
use tokio::time;

use crate::Conformance;
use crate::check::{CheckOutcome, PASS, SeenChunks, fail, numbered_lines, skip};

pub(super) async fn exec_streams_stdin(ctx: &Conformance) -> CheckOutcome {
    ctx.require(Capability::ExecStdinStream)?;
    ctx.with_ready(|sandbox| async move {
        if !sandbox.capabilities().exec.stdin_stream {
            return skip("exec.stdin_stream not declared for this sandbox");
        }
        let source = StdinSource::new(Cursor::new(b"streamed".to_vec()));
        let controls = ExecControls {
            stdin: Some(source),
            ..ExecControls::buffered()
        };
        let spec = ExecSpec::new("cat").timeout(Duration::from_secs(30));
        let streaming = sandbox
            .exec()
            .run_streaming(&spec, controls)
            .await
            .map_err(|error| format!("exec failed: {error}"))?;
        if streaming.result.stdout != b"streamed" {
            return fail(format!(
                "streamed stdin not delivered: {:?}",
                streaming.result.stdout_lossy()
            ));
        }
        PASS
    })
    .await
}

pub(super) async fn exec_streaming_is_honest(ctx: &Conformance) -> CheckOutcome {
    ctx.with_ready(|sandbox| async move {
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
        let spec =
            ExecSpec::bash("echo to-stdout; echo to-stderr >&2").timeout(Duration::from_secs(30));
        let streaming = sandbox
            .exec()
            .run_streaming(&spec, controls)
            .await
            .map_err(|error| format!("exec failed: {error}"))?;
        if !streaming.result.success() {
            return fail(format!(
                "command failed: {}",
                streaming.result.stderr_lossy()
            ));
        }

        let caps = ctx.caps();
        if streaming.live_streaming && !caps.exec.live_streaming {
            return fail("result claims live_streaming but the capability is not declared");
        }
        if streaming.streams_separated && !caps.exec.streams_separated {
            return fail("result claims streams_separated but the capability is not declared");
        }

        let seen = chunks.lock().expect("chunks lock").clone();
        let all: Vec<u8> = seen.iter().flat_map(|(_, chunk)| chunk.clone()).collect();
        let text = String::from_utf8_lossy(&all);
        if !text.contains("to-stdout") {
            return fail("sink never saw stdout output");
        }
        if streaming.streams_separated {
            let stderr: Vec<u8> = seen
                .iter()
                .filter(|(stream, _)| *stream == OutputStream::Stderr)
                .flat_map(|(_, chunk)| chunk.clone())
                .collect();
            if !String::from_utf8_lossy(&stderr).contains("to-stderr") {
                return fail("streams_separated is set but stderr never arrived on stderr");
            }
        }
        PASS
    })
    .await
}

/// Every line of a large output reaches a slow sink, in order, with no
/// truncation: the drain after the command exits is bounded by silence,
/// not by a clock the consumer can miss.
pub(super) async fn exec_streams_large_output_in_order(ctx: &Conformance) -> CheckOutcome {
    const LINES: usize = 20_000;
    if !ctx.caps().exec.live_streaming {
        return skip("capability exec.live_streaming not declared");
    }
    ctx.with_ready(|sandbox| async move {
        let seen: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
        let sink_seen = Arc::clone(&seen);
        let controls = ExecControls {
            sink: Some(Arc::new(move |stream, chunk| {
                let seen = Arc::clone(&sink_seen);
                Box::pin(async move {
                    // A consumer that is busy between chunks, like a host
                    // writing a log under load.
                    time::sleep(Duration::from_millis(5)).await;
                    if stream == OutputStream::Stdout {
                        seen.lock().expect("seen lock").extend_from_slice(&chunk);
                    }
                    Ok(())
                })
            })),
            retained_output_limit: Some(0),
            ..ExecControls::buffered()
        };
        let spec = ExecSpec::bash(format!("seq 1 {LINES}")).timeout(Duration::from_secs(300));
        let streaming = sandbox
            .exec()
            .run_streaming(&spec, controls)
            .await
            .map_err(|error| format!("exec failed: {error}"))?;
        if !streaming.result.success() {
            return fail(format!(
                "command failed: {}",
                streaming.result.stderr_lossy()
            ));
        }
        if streaming.stdout_capture.truncated {
            return fail("stdout was reported truncated");
        }
        let expected = numbered_lines(LINES);
        let seen = seen.lock().expect("seen lock").clone();
        if seen != expected {
            let lines = seen.split(|byte| *byte == b'\n').count().saturating_sub(1);
            return fail(format!(
                "{lines} of {LINES} lines arrived ({} of {} bytes), or out of order",
                seen.len(),
                expected.len()
            ));
        }
        PASS
    })
    .await
}

/// Output is bytes, not lines: a final line without a newline arrives
/// exactly as written, buffered and streamed alike.
pub(super) async fn exec_output_keeps_a_partial_last_line(ctx: &Conformance) -> CheckOutcome {
    ctx.with_ready(|sandbox| async move {
        let spec = ExecSpec::bash("printf 'a\\nb'").timeout(Duration::from_secs(30));
        let buffered = sandbox
            .exec()
            .run(&spec)
            .await
            .map_err(|error| format!("exec failed: {error}"))?;
        if buffered.stdout != b"a\nb" {
            return fail(format!(
                "buffered stdout was {:?}, expected {:?}",
                String::from_utf8_lossy(&buffered.stdout),
                "a\nb"
            ));
        }
        if !ctx.caps().exec.live_streaming {
            return PASS;
        }
        let seen: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
        let sink_seen = Arc::clone(&seen);
        let controls = ExecControls {
            sink: Some(Arc::new(move |stream, chunk| {
                let seen = Arc::clone(&sink_seen);
                Box::pin(async move {
                    if stream == OutputStream::Stdout {
                        seen.lock().expect("seen lock").extend_from_slice(&chunk);
                    }
                    Ok(())
                })
            })),
            retained_output_limit: Some(0),
            ..ExecControls::buffered()
        };
        let streaming = sandbox
            .exec()
            .run_streaming(&spec, controls)
            .await
            .map_err(|error| format!("streaming exec failed: {error}"))?;
        if !streaming.result.success() {
            return fail("streaming command failed");
        }
        let seen = seen.lock().expect("seen lock").clone();
        if seen != b"a\nb" {
            return fail(format!(
                "streamed stdout was {:?}, expected {:?}",
                String::from_utf8_lossy(&seen),
                "a\nb"
            ));
        }
        PASS
    })
    .await
}

pub(super) async fn exec_retention_accounting_is_consistent(ctx: &Conformance) -> CheckOutcome {
    ctx.with_ready(|sandbox| async move {
        let controls = ExecControls {
            retained_output_limit: Some(512),
            ..ExecControls::buffered()
        };
        let spec = ExecSpec::bash("for i in $(seq 1 500); do echo payload-line-$i; done")
            .timeout(Duration::from_secs(60));
        let streaming = sandbox
            .exec()
            .run_streaming(&spec, controls)
            .await
            .map_err(|error| format!("exec failed: {error}"))?;
        let stats = streaming.stdout_capture;
        if stats.observed_bytes > 0
            && stats.retained_bytes + stats.omitted_bytes != stats.observed_bytes
        {
            return fail(format!("capture accounting inconsistent: {stats:?}"));
        }
        if stats.observed_bytes > 0 && streaming.result.stdout.len() > 512 {
            return fail(format!(
                "retained output exceeds the cap: {} bytes",
                streaming.result.stdout.len()
            ));
        }
        PASS
    })
    .await
}

/// One slow consumer of one stream must not stall other execs on the
/// same sandbox: while a deliberately slow sink drains a steady stream,
/// a second exec and a `describe` must both complete promptly, and each
/// sink must see only its own exec's output, in order.
pub(super) async fn concurrent_streams_do_not_starve_each_other(ctx: &Conformance) -> CheckOutcome {
    if !ctx.caps().exec.live_streaming {
        return skip("capability exec.live_streaming not declared");
    }
    ctx.with_ready(|sandbox| async move {
        // Slow stream: a line every 50ms, consumed at 600ms/chunk, so a
        // shared-pipe client accumulates a deep backlog quickly.
        let slow_chunks: SeenChunks = Arc::new(Mutex::new(Vec::new()));
        let slow_sink_chunks = Arc::clone(&slow_chunks);
        let slow_controls = ExecControls {
            sink: Some(Arc::new(move |stream, chunk| {
                let chunks = Arc::clone(&slow_sink_chunks);
                Box::pin(async move {
                    time::sleep(Duration::from_millis(600)).await;
                    chunks.lock().expect("chunks lock").push((stream, chunk));
                    Ok(())
                })
            })),
            ..ExecControls::buffered()
        };
        let slow_spec = ExecSpec::bash("for i in $(seq 1 20); do echo slow-$i; sleep 0.05; done")
            .timeout(Duration::from_secs(60));
        let slow_exec = sandbox.exec();
        let mut slow_task = std::pin::pin!(slow_exec.run_streaming(&slow_spec, slow_controls));
        let mut slow_done = None;

        // Let the slow stream start producing before racing it.
        tokio::select! {
            outcome = &mut slow_task => {
                slow_done = Some(outcome);
            }
            () = time::sleep(Duration::from_millis(700)) => {}
        }
        if slow_done.is_some() {
            return fail("slow exec finished before the race began".to_owned());
        }

        // Fast exec with its own sink, plus a describe, both timed.
        let fast_chunks: SeenChunks = Arc::new(Mutex::new(Vec::new()));
        let fast_sink_chunks = Arc::clone(&fast_chunks);
        let fast_controls = ExecControls {
            sink: Some(Arc::new(move |stream, chunk| {
                let chunks = Arc::clone(&fast_sink_chunks);
                Box::pin(async move {
                    chunks.lock().expect("chunks lock").push((stream, chunk));
                    Ok(())
                })
            })),
            ..ExecControls::buffered()
        };
        let fast_spec = ExecSpec::new("echo")
            .arg("fast-done")
            .timeout(Duration::from_secs(30));
        let race_started = Instant::now();
        let mut fast_and_describe = std::pin::pin!(async {
            tokio::join!(
                sandbox.exec().run_streaming(&fast_spec, fast_controls),
                sandbox.describe(),
            )
        });
        // Race the fast pair against the still-flowing slow stream,
        // continuing to poll the slow stream so its chunks keep moving.
        let (fast, described) = loop {
            tokio::select! {
                outcome = &mut fast_and_describe => break outcome,
                slow = &mut slow_task, if slow_done.is_none() => {
                    slow_done = Some(slow);
                }
            }
        };
        let raced = race_started.elapsed();
        let fast = fast.map_err(|error| format!("fast exec failed: {error}"))?;
        described.map_err(|error| format!("describe during streaming failed: {error}"))?;
        if !fast.result.success() {
            return fail("fast exec did not succeed".to_owned());
        }
        if raced > Duration::from_secs(4) {
            return fail(format!(
                "a slow consumer starved concurrent calls: fast exec + describe took {raced:?}"
            ));
        }

        // Cross-contamination and ordering.
        let fast_seen: Vec<u8> = fast_chunks
            .lock()
            .expect("chunks lock")
            .iter()
            .flat_map(|(_, chunk)| chunk.clone())
            .collect();
        let fast_text = String::from_utf8_lossy(&fast_seen);
        if !fast_text.contains("fast-done") || fast_text.contains("slow-") {
            return fail(format!("fast sink saw wrong output: {fast_text:?}"));
        }

        // Drain the slow exec to completion and verify its stream.
        let slow = match slow_done {
            Some(slow) => slow,
            None => slow_task.await,
        }
        .map_err(|error| format!("slow exec failed: {error}"))?;
        if !slow.result.success() {
            return fail("slow exec did not succeed".to_owned());
        }
        let slow_seen: Vec<u8> = slow_chunks
            .lock()
            .expect("chunks lock")
            .iter()
            .flat_map(|(_, chunk)| chunk.clone())
            .collect();
        let slow_text = String::from_utf8_lossy(&slow_seen);
        if slow_text.contains("fast-done") {
            return fail("slow sink saw the fast exec's output".to_owned());
        }
        let mut last = 0u32;
        for line in slow_text.lines().filter(|line| line.starts_with("slow-")) {
            let Ok(number) = line.trim_start_matches("slow-").parse::<u32>() else {
                continue;
            };
            if number <= last {
                return fail(format!("slow stream out of order at {line}"));
            }
            last = number;
        }
        if last != 20 {
            return fail(format!("slow stream incomplete: last line slow-{last}"));
        }
        PASS
    })
    .await
}
