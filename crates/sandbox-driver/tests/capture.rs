#![cfg(unix)]

use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::{env, fs, process};

use sandbox_driver::{
    DEFAULT_CAPTURE_BYTES, Error, ExecControls, ExecSpec, MutationOutcome, OutputSink,
    OutputStream, Sandbox, Sandboxes, Termination, run_captured, run_captured_with,
};
use sandbox_driver_testing::{FakeExec, FakeProvider};
use tokio::time;
use tokio_util::sync::CancellationToken;

/// A sandbox on a fake that answers `argv` with `response`.
async fn scripted(argv: Vec<String>, response: FakeExec) -> (Sandboxes, Box<dyn Sandbox>) {
    let fake = FakeProvider::new();
    fake.script(argv, response).await;
    let catalog = fake.sandboxes();
    let sandbox = catalog
        .builder("default")
        .await
        .expect("builder")
        .create()
        .await
        .expect("create");
    (catalog, sandbox)
}

fn build() -> Vec<String> {
    vec!["build".to_owned()]
}

/// Controls that pass every chunk on to `sink`.
fn forwarding(sink: OutputSink) -> ExecControls {
    ExecControls {
        sink: Some(sink),
        ..ExecControls::default()
    }
}

/// Returns the future unchanged; compiling proves a spawned task or an
/// `async_trait` method can await it.
fn spawnable<F: Future + Send>(future: F) -> F {
    future
}

#[tokio::test]
async fn a_failing_command_is_a_result_with_both_streams_and_its_exit_code() {
    let (_catalog, sandbox) = scripted(build(), FakeExec {
        stdout: b"compiled 3 files\n".to_vec(),
        stderr: b"error: missing semicolon\n".to_vec(),
        exit_code: 2,
        ..FakeExec::default()
    })
    .await;
    let captured = spawnable(run_captured(sandbox.as_ref(), ExecSpec::argv(build())))
        .await
        .expect("a failing command still completes");
    assert_eq!(captured.outcome.termination, Termination::Exited);
    assert_eq!(captured.outcome.exit_code, Some(2));
    assert_eq!(captured.stdout.bytes, b"compiled 3 files\n");
    assert_eq!(captured.stderr.bytes, b"error: missing semicolon\n");
    assert!(!captured.success());
    assert!(captured.is_complete());
}

#[tokio::test]
async fn output_beyond_the_limit_is_counted_not_kept_and_the_command_still_finishes() {
    let (_catalog, sandbox) = scripted(build(), FakeExec {
        stdout: b"0123456789".to_vec(),
        stderr: b"ok".to_vec(),
        ..FakeExec::default()
    })
    .await;
    let captured = spawnable(run_captured_with(
        sandbox.as_ref(),
        ExecSpec::argv(build()),
        ExecControls::default(),
        4,
    ))
    .await
    .expect("run");
    assert_eq!(captured.stdout.bytes, b"0189");
    assert_eq!(captured.stdout.omitted_bytes, 6);
    assert_eq!(captured.stdout.observed_bytes(), 10);
    // The limit is per stream: stderr fits and is whole.
    assert_eq!(captured.stderr.bytes, b"ok");
    assert_eq!(captured.stderr.omitted_bytes, 0);
    assert!(captured.success());
    assert!(!captured.is_complete());
    // Output can carry credentials, so `Debug` reports sizes only.
    let debug = format!("{captured:?}");
    assert!(
        !debug.contains(&format!("{:?}", captured.stdout.bytes)),
        "{debug}"
    );
}

#[tokio::test]
async fn the_callers_sink_sees_every_chunk_even_when_nothing_is_kept() {
    let (_catalog, sandbox) = scripted(build(), FakeExec {
        stdout: b"out".to_vec(),
        stderr: b"err".to_vec(),
        ..FakeExec::default()
    })
    .await;
    let seen = Arc::new(Mutex::new(Vec::new()));
    let sink: OutputSink = {
        let seen = Arc::clone(&seen);
        Arc::new(move |stream, bytes| {
            seen.lock().expect("seen").push((stream, bytes));
            Box::pin(async { Ok(()) })
        })
    };
    let captured = run_captured_with(
        sandbox.as_ref(),
        ExecSpec::argv(build()),
        forwarding(sink),
        0,
    )
    .await
    .expect("run");
    assert_eq!(*seen.lock().expect("seen"), [
        (OutputStream::Stdout, b"out".to_vec()),
        (OutputStream::Stderr, b"err".to_vec()),
    ]);
    assert!(captured.stdout.bytes.is_empty());
    assert_eq!(captured.stdout.omitted_bytes, 3);
    assert_eq!(captured.stderr.omitted_bytes, 3);
}

#[tokio::test(start_paused = true)]
async fn the_duration_covers_the_whole_exec_including_the_callers_sink() {
    let (_catalog, sandbox) = scripted(build(), FakeExec {
        stdout: b"out".to_vec(),
        stderr: b"err".to_vec(),
        ..FakeExec::default()
    })
    .await;
    // The clock is paused, so only these sleeps advance it: one per chunk.
    let sink: OutputSink = Arc::new(|_, _| {
        Box::pin(async {
            time::sleep(Duration::from_secs(2)).await;
            Ok(())
        })
    });
    let captured = run_captured_with(
        sandbox.as_ref(),
        ExecSpec::argv(build()),
        forwarding(sink),
        DEFAULT_CAPTURE_BYTES,
    )
    .await
    .expect("run");
    assert_eq!(captured.duration, Duration::from_secs(4));
}

#[tokio::test]
async fn a_failing_caller_sink_fails_the_run() {
    let (_catalog, sandbox) = scripted(build(), FakeExec {
        stdout: b"out".to_vec(),
        ..FakeExec::default()
    })
    .await;
    let sink: OutputSink = Arc::new(|_, _| {
        Box::pin(async {
            Err(Error::Transport {
                message: "consumer went away".into(),
                outcome: MutationOutcome::Unknown,
            })
        })
    });
    let result = run_captured_with(
        sandbox.as_ref(),
        ExecSpec::argv(build()),
        forwarding(sink),
        DEFAULT_CAPTURE_BYTES,
    )
    .await;
    assert!(
        matches!(&result, Err(Error::Transport { message, .. }) if message == "consumer went away"),
        "{result:?}"
    );
}

#[tokio::test]
async fn the_callers_stop_token_reaches_the_command_and_its_output_is_kept() {
    let (_catalog, sandbox) = scripted(build(), FakeExec {
        stdout: b"started\n".to_vec(),
        wait_for_stop: true,
        ..FakeExec::default()
    })
    .await;
    let term = CancellationToken::new();
    let sink: OutputSink = {
        let term = term.clone();
        Arc::new(move |_, _| {
            term.cancel();
            Box::pin(async { Ok(()) })
        })
    };
    let captured = run_captured_with(
        sandbox.as_ref(),
        ExecSpec::argv(build()),
        ExecControls {
            term: Some(term),
            ..forwarding(sink)
        },
        DEFAULT_CAPTURE_BYTES,
    )
    .await
    .expect("a stopped command still completes");
    assert_eq!(captured.outcome.termination, Termination::Terminated);
    assert_eq!(captured.stdout.bytes, b"started\n");
    assert!(!captured.success());
}

#[tokio::test]
async fn terminal_output_is_captured_as_stdout() {
    let (_catalog, sandbox) = scripted(build(), FakeExec {
        stdout: b"prompt$ ".to_vec(),
        stderr: b"warning".to_vec(),
        ..FakeExec::default()
    })
    .await;
    let mut spec = ExecSpec::argv(build());
    spec.tty = true;
    let captured = run_captured(sandbox.as_ref(), spec).await.expect("run");
    assert_eq!(captured.stdout.bytes, b"prompt$ warning");
    assert!(captured.stderr.bytes.is_empty());
}

#[test]
fn a_bash_spec_passes_the_exit_status_through_and_reads_no_startup_file() {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let scratch = env::temp_dir().join(format!("bash-spec-{}-{nanos}", process::id()));
    fs::create_dir(&scratch).expect("scratch directory");
    // Bash sources the file `BASH_ENV` names before a `-c` script.
    let startup = scratch.join("startup.sh");
    fs::write(&startup, "echo sourced\n").expect("startup file");

    let spec = ExecSpec::bash("printf ran; exit 7");
    spec.validate().expect("a bash spec is a valid exec");
    // The argv run the way a provider does, with no shell in between: the
    // spec's env laid over a workload that names a startup file.
    let (program, args) = spec.argv.split_first().expect("argv");
    let output = Command::new(program)
        .args(args)
        .env_clear()
        .env("PATH", env::var("PATH").expect("PATH"))
        .env("BASH_ENV", &startup)
        .envs(&spec.env)
        .output()
        .expect("the test machine provides bash");
    assert_eq!(String::from_utf8_lossy(&output.stdout), "ran");
    assert_eq!(output.status.code(), Some(7));

    fs::remove_dir_all(&scratch).expect("cleanup");
}
