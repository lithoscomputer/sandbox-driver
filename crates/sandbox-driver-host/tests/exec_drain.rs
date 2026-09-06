//! Stop controls stay live while an exited process's output is still draining.

use std::future;
use std::sync::Arc;
use std::time::Duration;

use sandbox_driver::{
    Error, ExecControls, ExecSpec, SandboxProvider, SandboxSource, SandboxSpec, Termination,
};
use sandbox_driver_host::HostProvider;
use tokio::sync::{Barrier, Notify};
use tokio::task::JoinSet;
use tokio::time;
use tokio_util::sync::CancellationToken;

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn concurrent_sandboxes_do_not_keep_each_others_output_open() {
    let provider = HostProvider::new();
    let mut sandboxes = Vec::new();
    for _ in 0..8 {
        sandboxes.push(
            provider
                .create(&SandboxSpec::new(SandboxSource::HostDirectory), None)
                .await
                .expect("sandbox"),
        );
    }
    let barrier = Arc::new(Barrier::new(sandboxes.len()));
    let mut jobs = JoinSet::new();
    for sandbox in &sandboxes {
        let sandbox = Arc::clone(sandbox);
        let barrier = Arc::clone(&barrier);
        jobs.spawn(async move {
            barrier.wait().await;
            for _ in 0..16 {
                let result = sandbox
                    .exec()
                    .run(&ExecSpec::bash("printf stdout; printf stderr >&2"))
                    .await?;
                assert!(result.success());
                assert_eq!(result.stdout, b"stdout");
                assert_eq!(result.stderr, b"stderr");
            }
            Ok::<(), Error>(())
        });
    }
    let mut outcomes = Vec::new();
    while let Some(outcome) = jobs.join_next().await {
        outcomes.push(outcome);
    }
    // Keep the sentinels alive until every command has drained its own
    // pipes. Teardown must not hide a pipe inherited by another sandbox.
    for sandbox in sandboxes {
        sandbox.delete().await.expect("delete sandbox");
    }
    for outcome in outcomes {
        outcome.expect("command task").expect("complete output");
    }
}

#[tokio::test]
async fn kill_interrupts_a_blocked_output_drain() {
    for leader_exits in [false, true] {
        blocked_drain(leader_exits, false).await;
    }
}

#[tokio::test]
async fn timeout_interrupts_a_blocked_output_drain() {
    for leader_exits in [false, true] {
        blocked_drain(leader_exits, true).await;
    }
}

async fn blocked_drain(leader_exits: bool, timeout: bool) {
    let sandbox = HostProvider::new()
        .create(&SandboxSpec::new(SandboxSource::HostDirectory), None)
        .await
        .expect("sandbox");
    let entered = Arc::new(Notify::new());
    let sink_entered = Arc::clone(&entered);
    let kill = CancellationToken::new();
    let controls = ExecControls {
        kill: Some(kill.clone()),
        sink: Some(Arc::new(move |_, _| {
            sink_entered.notify_one();
            Box::pin(future::pending())
        })),
        retained_output_limit: Some(2),
        ..ExecControls::buffered()
    };
    let script = if leader_exits {
        "printf output"
    } else {
        "printf output; exec sleep 300"
    };
    let spec = if timeout {
        ExecSpec::bash(script).timeout(Duration::from_millis(300))
    } else {
        ExecSpec::bash(script).no_timeout()
    };
    let exec = sandbox.exec();
    let outcome = time::timeout(Duration::from_secs(3), async {
        tokio::join!(exec.run_streaming(&spec, controls), async {
            entered.notified().await;
            if !timeout {
                // The short leader has time to exit; the other case proves
                // a kill before exit also skips a blocked final drain.
                if leader_exits {
                    time::sleep(Duration::from_millis(150)).await;
                }
                kill.cancel();
            }
        })
        .0
    })
    .await;
    sandbox.delete().await.expect("cleanup");
    let result = outcome
        .expect("a blocked sink cannot extend the stop by ten seconds")
        .expect("exec");
    assert_eq!(
        result.result.termination,
        if timeout {
            Termination::TimedOut
        } else {
            Termination::Killed
        }
    );
    assert_eq!(result.result.stdout, b"ot");
    assert_eq!(result.stdout_capture.observed_bytes, 6);
    assert_eq!(result.stdout_capture.omitted_bytes, 4);
    assert!(result.stdout_capture.truncated);
    assert!(result.stderr_capture.truncated);
}

#[tokio::test]
async fn term_reaches_descendants_while_an_exited_leaders_output_drains() {
    let sandbox = HostProvider::new()
        .create(&SandboxSpec::new(SandboxSource::HostDirectory), None)
        .await
        .expect("sandbox");
    let ready = Arc::new(Notify::new());
    let sink_ready = Arc::clone(&ready);
    let term = CancellationToken::new();
    let controls = ExecControls {
        term: Some(term.clone()),
        sink: Some(Arc::new(move |_, _| {
            sink_ready.notify_one();
            Box::pin(async { Ok(()) })
        })),
        ..ExecControls::buffered()
    };
    let spec = ExecSpec::bash(
        r#"
(
    trap 'printf "cleaned\n"; exit 0' TERM
    sleep 300 &
    echo ready > child-ready
    wait
) &
while [ ! -e child-ready ]; do :; done
printf 'ready\n'
"#,
    )
    .no_timeout();
    let exec = sandbox.exec();
    let outcome = time::timeout(Duration::from_secs(3), async {
        tokio::join!(exec.run_streaming(&spec, controls), async {
            ready.notified().await;
            time::sleep(Duration::from_millis(150)).await;
            term.cancel();
        })
        .0
    })
    .await;
    sandbox.delete().await.expect("cleanup");
    let result = outcome
        .expect("TERM reaches the descendant holding the output pipe")
        .expect("exec");
    assert_eq!(result.result.termination, Termination::Cancelled);
    assert_eq!(result.result.stdout, b"ready\ncleaned\n");
    assert!(!result.stdout_capture.truncated);
}

#[tokio::test]
async fn a_failed_sink_stops_descendants_without_waiting_for_the_other_stream() {
    let sandbox = HostProvider::new()
        .create(&SandboxSpec::new(SandboxSource::HostDirectory), None)
        .await
        .expect("sandbox");
    let controls = ExecControls {
        sink: Some(Arc::new(move |_, _| {
            Box::pin(async {
                // Let the leader exit while its descendant keeps stderr open.
                time::sleep(Duration::from_millis(150)).await;
                Err(Error::invalid_spec("test_sink", "the consumer failed"))
            })
        })),
        ..ExecControls::buffered()
    };
    let spec = ExecSpec::bash("sleep 300 & printf output").no_timeout();
    let outcome = time::timeout(
        Duration::from_secs(3),
        sandbox.exec().run_streaming(&spec, controls),
    )
    .await;
    sandbox.delete().await.expect("cleanup");
    let result = outcome
        .expect("a failed sink cancels the remaining output drain")
        .expect("exec");
    assert_eq!(result.result.termination, Termination::Cancelled);
    assert_eq!(result.result.stdout, b"output");
    assert!(result.stdout_capture.truncated);
    assert!(result.stderr_capture.truncated);
}
